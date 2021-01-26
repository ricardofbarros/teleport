/*
Copyright 2020 Gravitational, Inc.

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

// Package identityfile handles formatting and parsing of identity files.
package identityfile

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/kube/kubeconfig"
	"github.com/gravitational/teleport/lib/sshutils"

	"github.com/gravitational/trace"
)

// Format describes possible file formats how a user identity can be stored.
type Format string

const (
	// FormatFile is when a key + cert are stored concatenated into a single file
	FormatFile Format = "file"

	// FormatOpenSSH is OpenSSH-compatible format, when a key and a cert are stored in
	// two different files (in the same directory)
	FormatOpenSSH Format = "openssh"

	// FormatTLS is a standard TLS format used by common TLS clients (e.g. GRPC) where
	// certificate and key are stored in separate files.
	FormatTLS Format = "tls"

	// FormatKubernetes is a standard Kubernetes format, with all credentials
	// stored in a "kubeconfig" file.
	FormatKubernetes Format = "kubernetes"

	// FormatDatabase produces CA and key pair suitable for configuring a
	// database instance for mutual TLS.
	FormatDatabase Format = "db"

	// DefaultFormat is what Teleport uses by default
	DefaultFormat = FormatFile
)

// Write takes a username + their credentials and saves them to disk
// in a specified format.
//
// clusterAddr is only used with FormatKubernetes.
//
// filePath is used as a base to generate output file names; these names are
// returned in filesWritten.
func Write(filePath string, key *client.Key, format Format, clusterAddr string) (filesWritten []string, err error) {
	const (
		// the files and the dir will be created with these permissions:
		fileMode = 0600
		dirMode  = 0700
	)

	if filePath == "" {
		return nil, trace.BadParameter("identity output path is not specified")
	}

	switch format {
	// dump user identity into a single file:
	case FormatFile:
		filesWritten = append(filesWritten, filePath)
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		defer f.Close()

		// write key:
		if err := writeWithNewline(f, key.Priv); err != nil {
			return nil, trace.Wrap(err)
		}
		// append ssh cert:
		if err := writeWithNewline(f, key.Cert); err != nil {
			return nil, trace.Wrap(err)
		}
		// append tls cert:
		if err := writeWithNewline(f, key.TLSCert); err != nil {
			return nil, trace.Wrap(err)
		}
		// append trusted host certificate authorities
		for _, ca := range key.TrustedCA {
			// append ssh ca certificates
			for _, publicKey := range ca.HostCertificates {
				data, err := sshutils.MarshalAuthorizedHostsFormat(ca.ClusterName, publicKey, nil)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				if err := writeWithNewline(f, []byte(data)); err != nil {
					return nil, trace.Wrap(err)
				}
			}
			// append tls ca certificates
			for _, cert := range ca.TLSCertificates {
				if err := writeWithNewline(f, cert); err != nil {
					return nil, trace.Wrap(err)
				}
			}
		}

	// dump user identity into separate files:
	case FormatOpenSSH:
		keyPath := filePath
		certPath := keyPath + "-cert.pub"
		filesWritten = append(filesWritten, keyPath, certPath)

		err = ioutil.WriteFile(certPath, key.Cert, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		err = ioutil.WriteFile(keyPath, key.Priv, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

	case FormatTLS, FormatDatabase:
		keyPath := filePath + ".key"
		certPath := filePath + ".crt"
		casPath := filePath + ".cas"
		filesWritten = append(filesWritten, keyPath, certPath, casPath)

		err = ioutil.WriteFile(certPath, key.TLSCert, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		err = ioutil.WriteFile(keyPath, key.Priv, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		var caCerts []byte
		for _, ca := range key.TrustedCA {
			for _, cert := range ca.TLSCertificates {
				caCerts = append(caCerts, cert...)
			}
		}
		err = ioutil.WriteFile(casPath, caCerts, fileMode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

	case FormatKubernetes:
		filesWritten = append(filesWritten, filePath)
		if err := kubeconfig.Update(filePath, kubeconfig.Values{
			TeleportClusterName: key.ClusterName,
			ClusterAddr:         clusterAddr,
			Credentials:         key,
		}); err != nil {
			return nil, trace.Wrap(err)
		}

	default:
		return nil, trace.BadParameter("unsupported identity format: %q, use one of %q, %q, %q, %q or %q",
			format, FormatFile, FormatOpenSSH, FormatTLS, FormatKubernetes, FormatDatabase)
	}
	return filesWritten, nil
}

func writeWithNewline(w io.Writer, data []byte) error {
	if _, err := w.Write(data); err != nil {
		return trace.Wrap(err)
	}
	if !bytes.HasSuffix(data, []byte{'\n'}) {
		if _, err := fmt.Fprintln(w); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}
