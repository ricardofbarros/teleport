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

package protocol

import (
	"io"
	"net"

	"github.com/gravitational/trace"
)

// ReadPacket reads a protocol packet from the provided connection.
//
// MySQL wire protocol packet has the following structure:
//
//   4-byte
//   header      payload
//   ________    _________ ...
//  |        |  |
// xx xx xx xx xx xx xx xx ...
//  |_____|  |  |
//  payload  |  message
//  length   |  type
//           |
//           sequence
//           number
//
// https://dev.mysql.com/doc/internals/en/mysql-packet.html
func ReadPacket(conn net.Conn) (pkt []byte, pktType byte, err error) {
	// Read 4-byte packet header.
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, 0, trace.ConvertSystemError(err)
	}

	// First 3 header bytes is the payload length, the 4th is the sequence
	// number which we have no use for.
	payloadLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if payloadLen == 0 {
		return header[:], 0, nil
	}

	// Read the packet payload.
	// TODO(r0mant): Couple of improvements could be made here:
	// * Reuse buffers instead of allocating everything from scrach every time.
	// * Max payload size is 16Mb, support reading larger packets.
	payload := make([]byte, payloadLen)
	n, err := io.ReadFull(conn, payload)
	if err != nil {
		return nil, 0, trace.ConvertSystemError(err)
	}

	// First payload byte typically indicates the command type (query, quit,
	// etc) so return it separately.
	return append(header[:], payload[0:n]...), payload[0], nil
}

// WritePacket writes the provided protocol packet to the connection.
func WritePacket(pkt []byte, conn net.Conn) (int, error) {
	n, err := conn.Write(pkt)
	if err != nil {
		return 0, trace.ConvertSystemError(err)
	}
	return n, nil
}
