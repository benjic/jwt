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
	ErrMalformedToken = errors.New("malformed Content")
	// ErrBadSignature represents errors where a signature is invalid
	ErrBadSignature = errors.New("invalid Signature")
	// ErrAlgorithmNotImplemented is thrown if a given JWT is using an algorithm not implemented
	ErrAlgorithmNotImplemented = errors.New("requested algorithm is not implemented")
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

// A Decoder is a centeralized reader and key used to consume and verify a
// given JWT token.
type Decoder struct {
	reader    io.Reader
	validator Validator
}

// An Encoder is a centeralized writer and key used to take a given payload and
// produce a JWT token.
type Encoder struct {
	writer    io.Writer
	validator Validator
}

// A Header contains data related to the signature of the payload. This information
// is a consequence of the signing process and is for reference only.
// TODO: This should be private
type Header struct {
	Algorithm   Algorithm `json:"alg"`
	ContentType string    `json:"typ"`
	raw         []byte
}

// A JWT is a unified structure of the components of a JWT. This structure is
//used internally to aggregate components during encoding and decoding.
// TODO: This should be private
type JWT struct {
	Header            *Header
	headerRaw         []byte
	Payload           interface{}
	claimsPayload     *Payload
	payloadRaw        []byte
	registeredPayload Payload
	Signature         []byte
}

// NewDecoder creates an underlying Decoder with a given key and input reader
func NewDecoder(r io.Reader, v Validator) *Decoder {
	return &Decoder{reader: r, validator: v}
}

// Decode consumes the next available token from the given reader and populates
// a given interface with the matching values in the the token. The signature
// of the given token is verified and will return an error if a bad signature is
// found. In addition if the JWT is using an unimplemented algorithm an error will
// be returned as well.
func (dec *Decoder) Decode(v interface{}) error {

	buf := bufio.NewReader(dec.reader)
	input, err := buf.ReadString(byte(' '))

	jwt, err := parseJWT(input, v)

	if err != nil {
		return err
	}

	if valid, err := dec.validator.validate(jwt); !valid || err != nil {

		if err != nil {
			return err
		}

		return ErrBadSignature
	}

	return nil
}

// NewEncoder creates an underlying Encoder with a given key and output writer
func NewEncoder(w io.Writer, v Validator) *Encoder {
	return &Encoder{writer: w, validator: v}
}

// Encode takes a given payload and algorithm and composes a new signed JWT
// in the underlying writer. This will return an error in the event that the
// given payload cannot be encoded to JSON.
func (enc *Encoder) Encode(v interface{}) error {

	jwt := JWT{
		Header: &Header{
			ContentType: "JWT",
		},
		Payload: v,
	}

	if err := enc.validator.sign(&jwt); err != nil {
		return err
	}

	fmt.Fprintf(enc.writer, "%s", jwt.token())

	return nil
}

func (jwt *JWT) parseHeader(raw string) error {
	var err error
	var value []byte

	if value, err = parseField(raw); err != nil {
		return err
	}

	jwt.headerRaw = []byte(raw)

	if err = json.NewDecoder(bytes.NewReader(value)).Decode(jwt.Header); err != nil {
		return ErrMalformedToken
	}

	return err
}

func parseJWT(input string, payload interface{}) (*JWT, error) {
	var err error
	jwt := &JWT{
		Header:        &Header{},
		claimsPayload: &Payload{},
	}

	fields := strings.Split(input, ".")

	if len(fields) != 3 {
		return jwt, ErrMalformedToken
	}

	if err = jwt.parseHeader(fields[0]); err != nil {
		return jwt, ErrMalformedToken
	}

	if err = jwt.parsePayload(fields[1], payload); err != nil {
		return jwt, ErrMalformedToken
	}

	jwt.Signature = []byte(fields[2])

	return jwt, nil
}

func (jwt *JWT) token() string {
	header := strings.Trim(string(jwt.headerRaw), "=")
	payload := strings.Trim(string(jwt.payloadRaw), "=")
	signature := strings.Trim(string(jwt.Signature), "=")

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

func (jwt *JWT) parsePayload(raw string, v interface{}) error {
	jwt.payloadRaw = []byte(raw)
	value, err := parseField(raw)

	if err != nil {
		return err
	}

	// TODO: How to deal with json encoder errors?
	err = json.NewDecoder(bytes.NewReader(value)).Decode(v)

	if err != nil {
		return err
	}

	json.NewDecoder(bytes.NewReader(value)).Decode(jwt.claimsPayload)

	return nil
}

func parseField(b64Value string) ([]byte, error) {
	if m := len(b64Value) % 4; m != 0 {
		b64Value += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(b64Value)
}
