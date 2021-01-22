/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mysql

import (
	"context"
	"net"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/mysql/protocol"

	"github.com/siddontang/go-mysql/client"
	"github.com/siddontang/go-mysql/mysql"
	"github.com/siddontang/go-mysql/packet"
	"github.com/siddontang/go-mysql/server"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// Engine implements the MySQL database service that accepts client
// connections coming over reverse tunnel from the proxy and proxies
// them between the proxy and the MySQL database instance.
//
// Implements common.Engine.
type Engine struct {
	// Auth handles database access authentication.
	Auth *common.Auth
	// Audit emits database access audit events.
	Audit *common.Audit
	// Context is the database server close context.
	Context context.Context
	// Clock is the clock interface.
	Clock clockwork.Clock
	// Log is used for logging.
	Log logrus.FieldLogger
}

// HandleConnection processes the connection from MySQL proxy coming
// over reverse tunnel.
//
// It handles all necessary startup actions, authorization and acts as a
// middleman between the proxy and the database intercepting and interpreting
// all messages i.e. doing protocol parsing.
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *common.Session, clientConn net.Conn) (err error) {
	// Make server conn to get access to protocol's WriteOK/WriteError methods.
	proxyConn := server.Conn{Conn: packet.NewConn(clientConn)}
	defer func() {
		if err != nil {
			if err := proxyConn.WriteError(err); err != nil {
				e.Log.WithError(err).Error("Failed to send error to client.")
			}
		}
	}()
	// Perform authorization checks.
	err = e.checkAccess(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	// Establish connection to the MySQL server.
	serverConn, err := e.connect(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		err := serverConn.Close()
		if err != nil {
			e.Log.WithError(err).Error("Failed to close connection to MySQL server.")
		}
	}()
	// Send back OK packet to indicate auth/connect success. At this point
	// the original client should consider the connection phase completed.
	err = proxyConn.WriteOK(nil)
	if err != nil {
		return trace.Wrap(err)
	}
	err = e.Audit.OnSessionStart(e.Context, *sessionCtx, nil)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		err := e.Audit.OnSessionEnd(e.Context, *sessionCtx)
		if err != nil {
			e.Log.WithError(err).Error("Failed to emit audit event.")
		}
	}()
	// Copy between the connections.
	clientErrCh := make(chan error, 1)
	serverErrCh := make(chan error, 1)
	go e.receiveFromClient(clientConn, serverConn, clientErrCh, sessionCtx)
	go e.receiveFromServer(serverConn, clientConn, serverErrCh)
	select {
	case err := <-clientErrCh:
		e.Log.WithError(err).Debug("Client done.")
	case err := <-serverErrCh:
		e.Log.WithError(err).Debug("Server done.")
	case <-ctx.Done():
		e.Log.Debug("Context canceled.")
	}
	return nil
}

func (e *Engine) checkAccess(sessionCtx *common.Session) error {
	err := sessionCtx.Checker.CheckAccessToDatabase(sessionCtx.Server,
		sessionCtx.DatabaseName, sessionCtx.DatabaseUser)
	if err != nil {
		if err := e.Audit.OnSessionStart(e.Context, *sessionCtx, err); err != nil {
			e.Log.WithError(err).Error("Failed to emit audit event.")
		}
		return trace.Wrap(err)
	}
	return nil
}

// connect establishes connection to MySQL database.
func (e *Engine) connect(ctx context.Context, sessionCtx *common.Session) (*client.Conn, error) {
	tlsConfig, err := e.Auth.GetTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var password string
	if sessionCtx.Server.IsRDS() {
		password, err = e.Auth.GetRDSAuthToken(sessionCtx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	conn, err := client.Connect(sessionCtx.Server.GetURI(),
		sessionCtx.DatabaseUser,
		password,
		sessionCtx.DatabaseName,
		func(conn *client.Conn) {
			conn.SetTLSConfig(tlsConfig)
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return conn, nil
}

// receiveFromClient relays protocol messages received from MySQL client
// to MySQL database.
func (e *Engine) receiveFromClient(clientConn, serverConn net.Conn, clientErrCh chan<- error, sessionCtx *common.Session) {
	log := e.Log.WithField("from", "client")
	defer log.Debug("Stop receiving from client.")
	for {
		packet, packetType, err := protocol.ReadPacket(clientConn)
		if err != nil {
			log.WithError(err).Error("Failed to read client packet.")
			clientErrCh <- err
			return
		}
		switch packetType {
		case mysql.COM_QUERY:
			err := e.Audit.OnQuery(e.Context, *sessionCtx, string(packet[5:]))
			if err != nil {
				log.WithError(err).Error("Failed to emit audit event.")
			}
		case mysql.COM_QUIT:
			clientErrCh <- nil
			return
		}
		_, err = protocol.WritePacket(packet, serverConn)
		if err != nil {
			log.WithError(err).Error("Failed to write server packet.")
			clientErrCh <- err
			return
		}
	}
}

// receiveFromServer relays protocol messages received from MySQL database
// to MySQL client.
func (e *Engine) receiveFromServer(serverConn, clientConn net.Conn, serverErrCh chan<- error) {
	log := e.Log.WithField("from", "server")
	defer log.Debug("Stop receiving from server.")
	for {
		packet, _, err := protocol.ReadPacket(serverConn)
		if err != nil {
			if strings.Contains(err.Error(), teleport.UseOfClosedNetworkConnection) {
				log.Debug("Server connection closed.")
				serverErrCh <- nil
				return
			}
			log.WithError(err).Error("Failed to read server packet.")
			serverErrCh <- err
			return
		}
		_, err = protocol.WritePacket(packet, clientConn)
		if err != nil {
			log.WithError(err).Error("Failed to write client packet.")
			serverErrCh <- err
			return
		}
	}
}
