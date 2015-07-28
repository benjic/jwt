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
	"errors"
	"fmt"
	"io"
	"time"
)
import "encoding/json"

var (
	// ErrMalformedToken represent errors where the given JWT is improperly formed
	ErrMalformedToken = errors.New("Malformed Content")
)

// Header is a preamble in a JWT
type Header interface{}

// A Payload in a JWT represents a set of claims for a given token.
type Payload struct {
	Issuer         string     `json:"iss,omitempty"`
	Subject        string     `json:"sub,omitempty"`
	Audience       string     `json:"aud,omitempty"`
	ExpirationTime *time.Time `json:"exp,omitempty"`
	NotBefore      *time.Time `json:"nbf,omitempty"`
	IssuedAt       *time.Time `json:"iat,omitempty"`
	JWTId          string     `json:"jti,omitempty"`
	raw            []byte
}

// JWSDecoder is a JSON Web Signature
type JWSDecoder struct {
	reader io.Reader
	key    []byte
}

type JWSEncoder struct {
	writer io.Writer
	key    []byte
}

func NewJWTPayload(raw string, v interface{}) (*Payload, error) {
	var err error
	var value []byte
	payload := &Payload{raw: []byte(raw)}

	if value, err = parseField(raw); err != nil {
		return payload, err
	}

	if err := json.NewDecoder(bytes.NewReader(value)).Decode(v); err != nil {
		return payload, err
	}

	return payload, nil
}

// NewJWSDecoder creates a mechanism for verifying a given jws
func NewJWSDecoder(r io.Reader, key []byte) *JWSDecoder {
	JWSDecoder := &JWSDecoder{reader: r, key: key}
	return JWSDecoder
}

// Decode processes the next JWT from the input and stores it in the value pointed
// to by v.
func (dec *JWSDecoder) Decode(v interface{}) error {

	buf := bufio.NewReader(dec.reader)
	input, err := buf.ReadString(byte(' '))

	if err != nil && err != io.EOF {
		return ErrMalformedToken
	}

	jwt, err := NewJWS(input, v)

	if err != nil {
		return err
	}

	if valid, err := jwt.ValidateSignature(dec.key); !valid || err != nil {
		return ErrBadSignature
	}

	return nil
}

func NewJWSEncoder(w io.Writer, key []byte) *JWSEncoder {
	return &JWSEncoder{writer: w, key: key}
}

func (enc *JWSEncoder) Encode(v interface{}, alg algorithm) error {

	jws := JWS{
		Header: &JWSHeader{
			Algorithm:   alg,
			ContentType: "JWT",
		},
		Payload: v.(*Payload),
	}

	if err := jws.Sign(enc.key); err != nil {
		return err
	}

	fmt.Fprintf(enc.writer, "%s", jws.Token())

	return nil
}
