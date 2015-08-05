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

const (
	// HS256 is the HMAC SHA256 signing algorithm
	HS256 = "HS256"
	// HS384 is the HMAC SHA384 signing algorithm
	HS384 = "HS384"
	// HS512 is the HMAC SHA512 signing algorithm
	HS512 = "HS512"
	// None is the noop siging algorithm
	None = "none"
)

type nonevalidator struct{}

// An Algorithm describes the signing algorithm as defined by the JWT specficiation
type Algorithm string

// A Validator describes a pair of algorithmic operations that can be performed on
// a give JWT.
type Validator interface {
	// validate asserts if a given token is signed correctly
	validate(JWT *JWT) (bool, error)
	// Sign adds a new signature to a given JWT
	sign(JWT *JWT) error
}

func (v nonevalidator) validate(JWT *JWT) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v nonevalidator) sign(JWT *JWT) error {

	JWT.Header.Algorithm = None
	JWT.Signature = []byte("")

	// NOOP Signing :-1:
	return nil
}
