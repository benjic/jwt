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

package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const (
	// ES256 is the elliptic curve signing algorithm using 256 bits
	ES256 = "ES256"
	// ES384 is the elliptic curve signing algorithm using 384 bits
	ES384 = "ES384"
	// ES512 is the elliptic curve signing algorithm using 512 bits
	ES512 = "ES512"
	// HS256 is the HMAC SHA256 signing algorithm
	HS256 = "HS256"
	// HS384 is the HMAC SHA384 signing algorithm
	HS384 = "HS384"
	// HS512 is the HMAC SHA512 signing algorithm
	HS512 = "HS512"
	// None is the noop siging algorithm
	None = "none"
	// RS256 is a RSA algorithm using a SHA256 algorithm
	RS256 = "RS256"
	// RS384 is a RSA algorithm using a SHA384 algorithm
	RS384 = "RS384"
	// RS512 is a RSA algorithm using a SHA512 algorithm
	RS512 = "RS512"
)

type nonevalidator struct{}

// An Algorithm describes the signing algorithm as defined by the jwt specficiation
type Algorithm string

// A Validator describes a pair of algorithmic operations that can be performed on
// a give jwt.
type Validator interface {
	// validate asserts if a given token is signed correctly
	validate(jwt *jwt) (bool, error)
	// Sign adds a new signature to a given jwt
	sign(jwt *jwt) error
}

func (v nonevalidator) validate(jwt *jwt) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v nonevalidator) sign(jwt *jwt) error {

	jwt.Header.Algorithm = None
	jwt.Signature = []byte("")

	// NOOP Signing :-1:
	return nil
}

func (jwt *jwt) rawEncode() (header, payload []byte) {
	headerBuf := bytes.NewBuffer(nil)
	payloadBuf := bytes.NewBuffer(nil)

	json.NewEncoder(headerBuf).Encode(jwt.Header)
	json.NewEncoder(payloadBuf).Encode(jwt.Payload)

	compactHeaderBuf := bytes.NewBuffer(nil)
	compactPayloadBuf := bytes.NewBuffer(nil)

	json.Compact(compactHeaderBuf, headerBuf.Bytes())
	json.Compact(compactPayloadBuf, payloadBuf.Bytes())

	header = make([]byte, base64.URLEncoding.EncodedLen(len(compactHeaderBuf.Bytes())))
	payload = make([]byte, base64.URLEncoding.EncodedLen(len(compactPayloadBuf.Bytes())))

	base64.URLEncoding.Encode(header, compactHeaderBuf.Bytes())
	base64.URLEncoding.Encode(payload, compactPayloadBuf.Bytes())

	header = []byte(strings.Trim(string(header), "="))
	payload = []byte(strings.Trim(string(payload), "="))

	return header, payload
}
