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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"strings"
)

// A RSValidator implments the validator interface and allows the singing and verification
// of signatures with RSA PCSK1.5 algorithms.
type RSValidator struct {
	algorithm  Algorithm
	hashType   crypto.Hash
	hashFunc   func() hash.Hash
	randReader io.Reader
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// NewRSValidator constructs a RSValidator
func NewRSValidator(algorithm Algorithm) RSValidator {
	// TODO: Implement all sha algorithms
	return RSValidator{
		algorithm:  algorithm,
		hashType:   crypto.SHA256,
		hashFunc:   sha256.New,
		randReader: rand.Reader,
	}
}

func (v RSValidator) validate(jwt *JWT) (bool, error) {

	if v.PublicKey == nil {
		return false, ErrBadSignature
	}

	jwt.Header.Algorithm = v.algorithm
	jwt.rawEncode()

	signature, err := base64.URLEncoding.DecodeString(string(jwt.Signature))

	if err != nil {
		return false, err
	}

	hsh := v.hashFunc()
	hsh.Write([]byte(string(jwt.headerRaw) + "." + string(jwt.payloadRaw)))
	hash := hsh.Sum(nil)

	err = rsa.VerifyPKCS1v15(v.PublicKey, v.hashType, hash, signature)

	if err != nil {
		return false, ErrBadSignature
	}

	return true, nil
}

func (v RSValidator) sign(jwt *JWT) (err error) {
	jwt.Header.Algorithm = v.algorithm
	jwt.rawEncode()

	hsh := v.hashFunc()
	hsh.Write([]byte(string(jwt.headerRaw) + "." + string(jwt.payloadRaw)))
	hash := hsh.Sum(nil)

	signature, _ := rsa.SignPKCS1v15(v.randReader, v.PrivateKey, v.hashType, hash)
	jwt.Signature = []byte(strings.Trim(base64.URLEncoding.EncodeToString(signature), "="))

	return err
}
