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
	// TODO: Implement more algorithms
	hs256 = "hs256"
	none  = "none"
)

type algorithm string

// A Validator is a interface for a given signing algorithm
type Validator interface {
	Validate(jws *JWS, key []byte) (bool, error)
	Sign(jws *JWS, key []byte) ([]byte, error)
}

type NoneValidator struct{}
type hs256Validator struct{}

func (v NoneValidator) Validate(jws *JWS, key []byte) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v NoneValidator) Sign(jws *JWS, key []byte) ([]byte, error) {

	jws.Header.Algorithm = none

	// NOOP Signing :-1:
	return []byte(""), nil
}

func (v hs256Validator) Validate(jws *JWS, key []byte) (bool, error) {
	signature, _ := base64.StdEncoding.DecodeString(addBase64Padding(string(jws.Signature)))

	magicString := string(jws.Header.raw) + "." + string(jws.Payload.raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil)), nil
}

func (v hs256Validator) Sign(jws *JWS, key []byte) ([]byte, error) {

	jws.Header.Algorithm = hs256

	headerBuf := bytes.NewBuffer(nil)
	payloadBuf := bytes.NewBuffer(nil)

	if err := json.NewEncoder(headerBuf).Encode(jws.Header); err != nil {
		return []byte(nil), err
	}

	if err := json.NewEncoder(payloadBuf).Encode(jws.Payload); err != nil {
		return []byte(nil), err
	}

	b64Header := strings.Trim(base64.URLEncoding.EncodeToString(headerBuf.Bytes()), "=")
	b64Payload := strings.Trim(base64.URLEncoding.EncodeToString(payloadBuf.Bytes()), "=")

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64Header + "." + b64Payload))

	return mac.Sum(nil), nil
}
