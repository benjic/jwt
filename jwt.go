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
	"bytes"
	"errors"
	"time"
)
import "encoding/json"

var (
	// ErrMalformedToken represent errors where the given JWT is improperly formed
	ErrMalformedToken = errors.New("Malformed Content")
	// ErrBadSignature represents errors where a signature is invalid
	ErrBadSignature            = errors.New("Invalid Signature")
	ErrAlgorithmNotImplemented = errors.New("Requested algorithm is not implemented")
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
