// Copyright (C) 2013 Coşku Baş
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <http://www.gnu.org/licenses/>.

package kasa

import (
	"crypto/tls"
	"log"
	"net"
)

// Error, warning and log messages.
const (
	// Errors
	svLoadKeyPairErr = "[Error] Can't load key pair: %s"
	svListenErr      = "[Error] Can't listen: %s"

	// Warnings
	svAcceptWrn        = "[Warning] Connection is not accepted: %s"
	svTlsTypeAssertWrn = "[Warning] Connection is not of type TLS"
	svHandshakeWrn     = "[Warning] Handshake is unsuccessfull: %s"
)

// Server represents a new listener for connections.
type Server struct {
	listener net.Listener
}

// ServerConfig holds server settings.
type ServerConfig struct {
	ListenAddress string
	ListenPort    string
	PrivateKey    string
	PublicKey     string
}

// NewServer sets up a new server.
func NewServer(c *ServerConfig) *Server {
	// Load public/private keys
	keyPair, err := tls.LoadX509KeyPair(c.PublicKey, c.PrivateKey)
	if err != nil {
		log.Fatalf(svLoadKeyPairErr, err)
	}

	// Start listening
	tlsConfig := tls.Config{Certificates: []tls.Certificate{keyPair}, ClientAuth: tls.RequireAnyClientCert}
	listener, err := tls.Listen("tcp", net.JoinHostPort(c.ListenAddress, c.ListenPort), &tlsConfig)
	if err != nil {
		log.Fatalf(svListenErr, err)
	}

	return &Server{listener}
}

// Run runs the main loop of the server. A new goroutine of `handleClient` is created for every accepted connection.
func (s *Server) Run(handleClient func(c *tls.Conn)) {
	defer s.listener.Close()

	// Main loop
	for {
		// Wait for a connection
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf(svAcceptWrn, err)
			continue
		}

		// Type assertion to tls connection
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf(svTlsTypeAssertWrn)
			conn.Close()
			continue
		}

		// Handshake
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf(svHandshakeWrn, err)
			tlsConn.Close()
			continue
		}

		// Invoke handleClient
		go handleClient(tlsConn)
	}
}
