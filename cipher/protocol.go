// Copyright (c) 2019 Perlin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package cipher

import (
	"crypto"
	_ "crypto/sha512"
	"net"

	"github.com/perlin-network/noise"
	"github.com/perlin-network/noise/handshake"
	"golang.org/x/net/context"
)

type ProtocolAEAD struct{
	legacyHash bool
}

func NewAEAD(legacyHash bool) ProtocolAEAD {
	return ProtocolAEAD{legacyHash}
}

func (p ProtocolAEAD) Client(info noise.Info, _ context.Context, _ string, conn net.Conn) (net.Conn, error) {
	hashFn := crypto.SHA512_256.New
	if p.legacyHash {
		hashFn = crypto.SHA256.New
	}
	suite, _, err := DeriveAEAD(Aes256GCM(), hashFn, info.Bytes(handshake.SharedKey), nil)
	if err != nil {
		return nil, err
	}

	return newConnAEAD(suite, conn), nil
}

func (p ProtocolAEAD) Server(info noise.Info, conn net.Conn) (net.Conn, error) {
	hashFn := crypto.SHA512_256.New
	if p.legacyHash {
		hashFn = crypto.SHA256.New
	}
	suite, _, err := DeriveAEAD(Aes256GCM(), hashFn, info.Bytes(handshake.SharedKey), nil)
	if err != nil {
		return nil, err
	}

	return newConnAEAD(suite, conn), nil
}
