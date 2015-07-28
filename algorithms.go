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
	"strings"
)

const (
	HS256 = "HS256"
	None  = "none"
)

type algorithm string

// A Validator is a interface for a given signing algorithm
type Validator interface {
	Validate(jws *JWS, key []byte) (bool, error)
	Sign(jws *JWS, key []byte) error
}

type NoneValidator struct{}
type HS256Validator struct{}

func (v NoneValidator) Validate(jws *JWS, key []byte) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v NoneValidator) Sign(jws *JWS, key []byte) error {

	jws.Header.Algorithm = None
	jws.Signature = []byte("")

	// NOOP Signing :-1:
	return nil
}

func (v HS256Validator) Validate(jws *JWS, key []byte) (bool, error) {
	signature, _ := base64.URLEncoding.DecodeString(addBase64Padding(string(jws.Signature)))

	magicString := string(jws.Header.raw) + "." + string(jws.Payload.raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil)), nil
}

func (v HS256Validator) Sign(jws *JWS, key []byte) error {

	jws.Header.Algorithm = HS256

	headerBuf := bytes.NewBuffer(nil)
	payloadBuf := bytes.NewBuffer(nil)

	if err := json.NewEncoder(headerBuf).Encode(jws.Header); err != nil {
		return err
	}

	if err := json.NewEncoder(payloadBuf).Encode(jws.Payload); err != nil {
		return err
	}

	compactHeaderBuf := bytes.NewBuffer(nil)
	compactPayloadBuf := bytes.NewBuffer(nil)

	json.Compact(compactHeaderBuf, headerBuf.Bytes())
	json.Compact(compactPayloadBuf, payloadBuf.Bytes())

	jws.Header.raw = make([]byte, base64.URLEncoding.EncodedLen(len(compactHeaderBuf.Bytes())))
	jws.Payload.raw = make([]byte, base64.URLEncoding.EncodedLen(len(compactPayloadBuf.Bytes())))

	base64.URLEncoding.Encode(jws.Header.raw, compactHeaderBuf.Bytes())
	base64.URLEncoding.Encode(jws.Payload.raw, compactPayloadBuf.Bytes())

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Trim(string(jws.Header.raw), "=") + "." + strings.Trim(string(jws.Payload.raw), "=")))

	jws.Signature = []byte(base64.URLEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}
