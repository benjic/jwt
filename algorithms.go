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
	// HS256 is the HMAC SHA256 signing algorithm
	HS256 = "HS256"
	// None is the noop siging algorithm
	None = "none"
)

// An Algorithm describes the signing algorithm as defined by the JWT specficiation
type Algorithm string

// A validator describes a pair of algorithmic operations that can be performed on
// a give JWT.
type validator interface {
	// validate asserts if a given token is signed correctly
	validate(JWT *JWT, key []byte) (bool, error)
	// Sign adds a new signature to a given JWT
	sign(JWT *JWT, key []byte) error
}

type nonevalidator struct{}
type hs256validator struct{}

func (v nonevalidator) validate(JWT *JWT, key []byte) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v nonevalidator) sign(JWT *JWT, key []byte) error {

	JWT.Header.Algorithm = None
	JWT.Signature = []byte("")

	// NOOP Signing :-1:
	return nil
}

func (v hs256validator) validate(JWT *JWT, key []byte) (bool, error) {
	signature, _ := base64.URLEncoding.DecodeString(addBase64Padding(string(JWT.Signature)))

	magicString := string(JWT.Header.raw) + "." + string(JWT.Payload.raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil)), nil
}

func (v hs256validator) sign(JWT *JWT, key []byte) error {

	JWT.Header.Algorithm = HS256

	headerBuf := bytes.NewBuffer(nil)
	payloadBuf := bytes.NewBuffer(nil)

	if err := json.NewEncoder(headerBuf).Encode(JWT.Header); err != nil {
		return err
	}

	if err := json.NewEncoder(payloadBuf).Encode(JWT.Payload); err != nil {
		return err
	}

	compactHeaderBuf := bytes.NewBuffer(nil)
	compactPayloadBuf := bytes.NewBuffer(nil)

	json.Compact(compactHeaderBuf, headerBuf.Bytes())
	json.Compact(compactPayloadBuf, payloadBuf.Bytes())

	JWT.Header.raw = make([]byte, base64.URLEncoding.EncodedLen(len(compactHeaderBuf.Bytes())))
	JWT.Payload.raw = make([]byte, base64.URLEncoding.EncodedLen(len(compactPayloadBuf.Bytes())))

	base64.URLEncoding.Encode(JWT.Header.raw, compactHeaderBuf.Bytes())
	base64.URLEncoding.Encode(JWT.Payload.raw, compactPayloadBuf.Bytes())

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Trim(string(JWT.Header.raw), "=") + "." + strings.Trim(string(JWT.Payload.raw), "=")))

	JWT.Signature = []byte(base64.URLEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}
