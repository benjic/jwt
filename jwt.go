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

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
)
import (
	"encoding/base64"
	"encoding/json"
)

var (
	errMalformedContent = errors.New("Malformed Content")
	errBadSignature     = errors.New("Mismatched Signature")
)

// JWSDecoder is a JSON Web Signature
type JWSDecoder struct {
	reader io.Reader
	key    []byte
}

type jws struct {
	JOSE, Payload, Signature []byte
}

func newjws(input string) (*jws, error) {
	var err error
	jwt := &jws{}

	fields := strings.Split(input, ".")

	if len(fields) != 3 {
		return jwt, errMalformedContent
	}

	if jwt.JOSE, err = base64.URLEncoding.DecodeString(
		addBase64Padding(fields[0])); err != nil {
		return jwt, err
	}
	if jwt.Payload, err = base64.URLEncoding.DecodeString(
		addBase64Padding(fields[1])); err != nil {
		return jwt, err
	}
	if jwt.Signature, err = base64.URLEncoding.DecodeString(
		addBase64Padding(fields[2])); err != nil {
		return jwt, err
	}

	return jwt, nil
}

// NewJWSDecoder creates a mechanism for verifying a given jws
func NewJWSDecoder(r io.Reader) *JWSDecoder {
	JWSDecoder := &JWSDecoder{reader: r}
	return JWSDecoder
}

// Decode processes the next JWT from the input and stores it in the value pointed
// to by v.
func (dec *JWSDecoder) Decode(v interface{}) error {

	buf := bufio.NewReader(dec.reader)
	input, err := buf.ReadString(byte(' '))

	if err != nil && err != io.EOF {
		return errMalformedContent
	}

	jwt, err := newjws(input)

	if err != nil {
		return err
	}

	if jwt.hasValidSignature([]byte("secret")) {
		return json.NewDecoder(bytes.NewReader(jwt.Payload)).Decode(v)
	}

	return errBadSignature
}

func (jws *jws) hasValidSignature(key []byte) bool {

	b64JOSE := base64.StdEncoding.EncodeToString(jws.JOSE)
	b64Payload := base64.StdEncoding.EncodeToString(jws.Payload)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64JOSE + "." + b64Payload))

	return hmac.Equal(jws.Signature, mac.Sum(nil))
}

func addBase64Padding(encoded string) string {
	if m := len(encoded) % 4; m != 0 {
		encoded += strings.Repeat("=", 4-m)
	}
	return encoded
}
