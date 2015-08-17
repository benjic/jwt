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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// An ESValidator implments the validator interface and provides a signing and Validation
// tool for Elliptic curve signed tokens
type ESValidator struct {
	algorithm  Algorithm
	hashType   crypto.Hash
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	rand       io.Reader
}

// NewESValidator instantiates a new instance of a parameterized Elliptic validator
func NewESValidator(algorithm Algorithm) (v ESValidator, err error) {

	v = ESValidator{algorithm: algorithm, rand: rand.Reader}

	switch algorithm {
	case ES256:
		v.hashType = crypto.SHA256
		return v, err
	default:
		return v, ErrAlgorithmNotImplemented
	}
}

func (v ESValidator) sign(jwt *JWT) (err error) {
	if v.PrivateKey == nil {
		return errors.New("Cannot sign with a nil private key")
	}

	jwt.Header.Algorithm = v.algorithm
	jwt.rawEncode()

	// TODO: This block is general. Refactor it out of RS and ES validators
	hsh := v.hashType.New()
	hsh.Write([]byte(string(jwt.headerRaw) + "." + string(jwt.payloadRaw)))
	hash := hsh.Sum(nil)

	r, s, err := ecdsa.Sign(v.rand, v.PrivateKey, hash)

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	fmt.Printf("r: %+v\ns: %+v\n", r, s)
	jwt.Signature = make([]byte, base64.URLEncoding.EncodedLen(len(signature)))
	base64.URLEncoding.Encode(jwt.Signature, signature)
	fmt.Printf("%d\n", len(signature))

	return err
}

func (v ESValidator) validate(jwt *JWT) (bool, error) {
	r := new(big.Int)
	s := new(big.Int)

	if jwt.Signature == nil {
		return false, ErrBadSignature
	}

	signature := make([]byte, base64.URLEncoding.DecodedLen(len(jwt.Signature)))

	base64.URLEncoding.Decode(signature, jwt.Signature)

	if len(signature) != 66 {
		return false, ErrBadSignature
	}

	r.SetBytes(signature[0:32])
	s.SetBytes(signature[32:64])

	hsh := v.hashType.New()
	hsh.Write([]byte(string(jwt.headerRaw) + "." + string(jwt.payloadRaw)))
	hash := hsh.Sum(nil)

	fmt.Printf("r: %+v\ns: %+v\n", r, s)
	return ecdsa.Verify(v.PublicKey, hash, r, s), nil
}
