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
	"fmt"
	"net"
)

// Error, warning and log messages.
const (
	// Errors
	clLoadKeyPairErr = "[Error] Can't load key pair: %s"
	clDialErr        = "[Error] Can't dial: %s"
)

// Client holds a single connection to a server.
type Client struct {
	Conn *tls.Conn
}

// ClientConfig holds client settings.
type ClientConfig struct {
	ServerAddress string
	ServerPort    string
	PrivateKey    string
	PublicKey     string
}

// New client establishes a new connection between the server and client.
func NewClient(c *ClientConfig) (*Client, error) {
	// Load public/private keys
	keyPair, err := tls.LoadX509KeyPair(c.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf(clLoadKeyPairErr, err)
	}

	// Dial connection
	tlsConfig := tls.Config{Certificates: []tls.Certificate{keyPair}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", net.JoinHostPort(c.ServerAddress, c.ServerPort), &tlsConfig)
	if err != nil {
		return nil, fmt.Errorf(clDialErr, err)
	}

	return &Client{conn}, nil
}
