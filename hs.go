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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"
)

type hsValidator struct {
	algorithm Algorithm
	hashFunc  func() hash.Hash
	Key       []byte
}

func NewHSValidator(algorithm Algorithm) hsValidator {
	var hashFunc func() hash.Hash
	switch algorithm {
	case HS256:
		hashFunc = sha256.New
	case HS384:
		hashFunc = sha512.New384
	case HS512:
		hashFunc = sha512.New
	}

	return hsValidator{algorithm, hashFunc, []byte(nil)}
}

func (v hsValidator) validate(JWT *JWT) (bool, error) {
	b64Signature := string(JWT.Signature)
	if m := len(b64Signature) % 4; m != 0 {
		b64Signature += strings.Repeat("=", 4-m)
	}

	if JWT.Header.Algorithm != v.algorithm {
		return false, ErrAlgorithmNotImplemented
	}

	signature, err := base64.URLEncoding.DecodeString(b64Signature)

	if err != nil {
		return false, ErrMalformedToken
	}

	magicString := string(JWT.headerRaw) + "." + string(JWT.payloadRaw)
	mac := hmac.New(v.hashFunc, v.Key)
	mac.Write([]byte(magicString))

	return hmac.Equal(signature, mac.Sum(nil)), nil
}

func (v hsValidator) sign(JWT *JWT) error {

	JWT.Header.Algorithm = v.algorithm
	JWT.rawEncode()

	mac := hmac.New(v.hashFunc, v.Key)
	mac.Write([]byte(strings.Trim(string(JWT.headerRaw), "=") + "." + strings.Trim(string(JWT.payloadRaw), "=")))

	JWT.Signature = []byte(base64.URLEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}
