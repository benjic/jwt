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
	"fmt"
	"io"
	"strings"
)

// JWSDecoder is a JSON Web Signature
type JWSDecoder struct {
	reader io.Reader
	key    []byte
}

type JWSEncoder struct {
	writer io.Writer
	key    []byte
}

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

// ValidateSignature uses the header of a given JWS to determine a the signing algorithm
// and validates it. Can return an errAlgorithmNotImplemented if using a not yet implemented
// signing method.
func (jws *JWS) ValidateSignature(key []byte) (bool, error) {
	var validator Validator
	var err error

	if validator, err = getValidator(jws.Header.Algorithm); err != nil {
		return false, err
	}

	return validator.Validate(jws, key)
}

func (jws *JWS) Sign(key []byte) error {
	var validator Validator
	var err error

	if validator, err = getValidator(jws.Header.Algorithm); err != nil {
		return err
	}

	validator.Sign(jws, key)

	return nil
}

func (jws *JWS) Token() string {
	header := string(jws.Header.raw)
	payload := string(jws.Payload.raw)
	signature := string(jws.Signature)

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

func getValidator(alg algorithm) (Validator, error) {
	switch alg {
	case HS256:
		return HS256Validator{}, nil
	case None:
		return NoneValidator{}, nil
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
