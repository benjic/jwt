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

// An ESValidator implments the validator interface and provides a signing and Validation
// tool for Elliptic curve signed tokens
type ESValidator struct{}

// NewESValidator instantiates a new instance of a parameterized Elliptic validator
func NewESValidator(algorithm Algorithm) (v ESValidator, err error) {
	switch algorithm {
	case ES256:
		return v, err
	default:
		return v, ErrAlgorithmNotImplemented
	}
}

func (v ESValidator) sign(jwt *JWT) error { return nil }

func (v ESValidator) validate(jwt *JWT) (bool, error) { return false, nil }
