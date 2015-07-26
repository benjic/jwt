// Copyright 2015 Benjamin Campbell <benji@benjica.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package jwt a simple library for encoding and decoding JSON Web Tokens
package jwt

import "io"

// JWSDecoder is a JSON Web Signature
type JWSDecoder struct {
	reader io.Reader
	key    []byte
}

// NewJWSDecoder creates a mechanism for verifying a given JWS
func NewJWSDecoder(r io.Reader, key []byte) *JWSDecoder {
	jwsDecoder := &JWSDecoder{reader: r, key: key}
	return jwsDecoder
}

// Decode processes the next JWT from the input and stores it in the value pointed
// to by v.
func (dec *JWSDecoder) Decode(v interface{}) error {

	return nil
}
