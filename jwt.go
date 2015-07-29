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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	// ErrMalformedToken represent errors where the given JWT is improperly formed
	ErrMalformedToken = errors.New("Malformed Content")
	// ErrBadSignature represents errors where a signature is invalid
	ErrBadSignature = errors.New("Invalid Signature")
	// ErrAlgorithmNotImplemented is thrown if a given JWT is using an algorithm not implemented
	ErrAlgorithmNotImplemented = errors.New("Requested algorithm is not implemented")
)

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

func parsePayload(raw string, v interface{}) (*Payload, error) {
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

// Decoder is a JSON Web Signature
type Decoder struct {
	reader io.Reader
	key    []byte
}

type Encoder struct {
	writer io.Writer
	key    []byte
}

// A Header contains data related to the signature of the payload
type Header struct {
	Algorithm   Algorithm `json:"alg"`
	ContentType string    `json:"typ"`
	raw         []byte
}

// A JWT represents a JWT with a web signature
type JWT struct {
	Header    *Header
	Payload   *Payload
	Signature []byte
}

// NewDecoder creates a mechanism for verifying a given JWT
func NewDecoder(r io.Reader, key []byte) *Decoder {
	Decoder := &Decoder{reader: r, key: key}
	return Decoder
}

// Decode processes the next JWT from the input and stores it in the value pointed
// to by v.
func (dec *Decoder) Decode(v interface{}) error {

	buf := bufio.NewReader(dec.reader)
	input, err := buf.ReadString(byte(' '))

	if err != nil && err != io.EOF {
		return ErrMalformedToken
	}

	jwt, err := parseJWT(input, v)

	if err != nil {
		return err
	}

	if valid, err := jwt.validateSignature(dec.key); !valid || err != nil {
		return ErrBadSignature
	}

	return nil
}

func NewEncoder(w io.Writer, key []byte) *Encoder {
	return &Encoder{writer: w, key: key}
}

func (enc *Encoder) Encode(v interface{}, alg Algorithm) error {

	JWT := JWT{
		Header: &Header{
			Algorithm:   alg,
			ContentType: "JWT",
		},
		Payload: v.(*Payload),
	}

	if err := JWT.sign(enc.key); err != nil {
		return err
	}

	fmt.Fprintf(enc.writer, "%s", JWT.Token())

	return nil
}

func parseHeader(raw string) (*Header, error) {
	var err error
	var value []byte
	header := &Header{raw: []byte(raw)}

	if value, err = parseField(raw); err != nil {
		return header, err
	}

	if err = json.NewDecoder(bytes.NewReader(value)).Decode(header); err != nil {
		return header, err
	}

	return header, err
}

func parseJWT(input string, payload interface{}) (*JWT, error) {
	var err error
	JWT := &JWT{}

	fields := strings.Split(input, ".")

	if len(fields) != 3 {
		return JWT, ErrMalformedToken
	}

	if JWT.Header, err = parseHeader(fields[0]); err != nil {
		return JWT, err
	}

	if JWT.Payload, err = parsePayload(fields[1], payload); err != nil {
		return JWT, err
	}

	JWT.Signature = []byte(fields[2])

	return JWT, nil
}

// validateSignature uses the header of a given JWT to determine a the signing algorithm
// and validates it. Can return an errAlgorithmNotImplemented if using a not yet implemented
// signing method.
func (JWT *JWT) validateSignature(key []byte) (bool, error) {
	var validator validator
	var err error

	if validator, err = getvalidator(JWT.Header.Algorithm); err != nil {
		return false, err
	}

	return validator.validate(JWT, key)
}

func (JWT *JWT) sign(key []byte) error {
	var validator validator
	var err error

	if validator, err = getvalidator(JWT.Header.Algorithm); err != nil {
		return err
	}

	validator.sign(JWT, key)

	return nil
}

func (JWT *JWT) Token() string {
	header := string(JWT.Header.raw)
	payload := string(JWT.Payload.raw)
	signature := string(JWT.Signature)

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

func getvalidator(alg Algorithm) (validator, error) {
	switch alg {
	case HS256:
		return hs256validator{}, nil
	case None:
		return nonevalidator{}, nil
	default:
		return nil, ErrAlgorithmNotImplemented
	}
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
