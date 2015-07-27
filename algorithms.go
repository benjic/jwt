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

func (v NoneValidator) Validate(jws *JWS, key []byte) (bool, error) {
	// NOOP Validation :-1:
	return true, nil
}

func (v NoneValidator) Sign(jws *JWS, key []byte) ([]byte, error) {
	// NOOP Signing :-1:
	return []byte(""), nil
}
