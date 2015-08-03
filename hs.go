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
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

type hsValidator struct{ hashFunc func() hash.Hash }

func newHSValidator(hashFunc func() hash.Hash) hsValidator {
	return hsValidator{hashFunc: hashFunc}
}

func (v hsValidator) validate(JWT *JWT, key []byte) (bool, error) {
	b64Signature := string(JWT.Signature)
	if m := len(b64Signature) % 4; m != 0 {
		b64Signature += strings.Repeat("=", 4-m)
	}

	signature, err := base64.URLEncoding.DecodeString(b64Signature)

	if err != nil {
		return false, ErrMalformedToken
	}

	magicString := string(JWT.headerRaw) + "." + string(JWT.payloadRaw)
	mac := hmac.New(v.hashFunc, key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil)), nil
}

func (v hsValidator) sign(JWT *JWT, key []byte) error {

	headerBuf := bytes.NewBuffer(nil)
	payloadBuf := bytes.NewBuffer(nil)

	// TODO: Determine if errors here are possible/relevant
	json.NewEncoder(headerBuf).Encode(JWT.Header)
	json.NewEncoder(payloadBuf).Encode(JWT.Payload)

	compactHeaderBuf := bytes.NewBuffer(nil)
	compactPayloadBuf := bytes.NewBuffer(nil)

	json.Compact(compactHeaderBuf, headerBuf.Bytes())
	json.Compact(compactPayloadBuf, payloadBuf.Bytes())

	JWT.headerRaw = make([]byte, base64.URLEncoding.EncodedLen(len(compactHeaderBuf.Bytes())))
	JWT.payloadRaw = make([]byte, base64.URLEncoding.EncodedLen(len(compactPayloadBuf.Bytes())))

	base64.URLEncoding.Encode(JWT.headerRaw, compactHeaderBuf.Bytes())
	base64.URLEncoding.Encode(JWT.payloadRaw, compactPayloadBuf.Bytes())

	mac := hmac.New(v.hashFunc, key)
	mac.Write([]byte(strings.Trim(string(JWT.headerRaw), "=") + "." + strings.Trim(string(JWT.payloadRaw), "=")))

	JWT.Signature = []byte(base64.URLEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}
