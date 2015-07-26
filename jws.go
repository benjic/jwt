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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type algorithm string

const (
	// TODO: Implement more algorithms
	hs256 = "hs256"
	none  = "none"
)

var (
	// ErrBadSignature represents errors where a signature is invalid
	ErrBadSignature = errors.New("Invalid Signature")
)

// A JWSHeader contains data related to the signature of the payload
type JWSHeader struct {
	Algorithm   algorithm `json:"alg"`
	ContentType string    `json:"typ"`
	raw         []byte
}

// A JWS represents a JWT with a web signature
type JWS struct {
	Header    *JWSHeader
	Payload   *Payload
	Signature []byte
}

func NewJWSHeader(raw string) (*JWSHeader, error) {
	var err error
	var value []byte
	header := &JWSHeader{raw: []byte(raw)}

	if value, err = parseField(raw); err != nil {
		return header, err
	}

	if err = json.NewDecoder(bytes.NewReader(value)).Decode(header); err != nil {
		return header, err
	}

	return header, err
}

func NewJWS(input string, payload interface{}) (*JWS, error) {
	var err error
	jws := &JWS{}

	fields := strings.Split(input, ".")

	if len(fields) != 3 {
		return jws, ErrMalformedToken
	}

	if jws.Header, err = NewJWSHeader(fields[0]); err != nil {
		return jws, err
	}

	if jws.Payload, err = NewJWTPayload(fields[1], payload); err != nil {
		return jws, err
	}

	jws.Signature = []byte(fields[2])

	return jws, nil
}

func (jws *JWS) ValidateSignature(key []byte) bool {
	signature, _ := base64.StdEncoding.DecodeString(addBase64Padding(string(jws.Signature)))

	magicString := string(jws.Header.raw) + "." + string(jws.Payload.raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil))
}

func parseField(b64Value string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(addBase64Padding(b64Value))
}

func addBase64Padding(encoded string) string {
	if m := len(encoded) % 4; m != 0 {
		encoded += strings.Repeat("=", 4-m)
	}
	return encoded
}
