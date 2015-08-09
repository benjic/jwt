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

import "testing"

func TestESSign(t *testing.T) {
	v, _ := NewESValidator(ES256)

	jwt := &JWT{
		Header: &Header{
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
	}

	//NOOP test
	v.sign(jwt)
}
func TestNewESValidator(t *testing.T) {
	cases := []struct {
		Algorithm     Algorithm
		ExpectedError error
		Reason        string
	}{
		{None, ErrAlgorithmNotImplemented, "did not expect to get a valid RS validator"},
	}

	for _, c := range cases {
		_, err := NewESValidator(c.Algorithm)

		if err != c.ExpectedError {
			t.Errorf("%s: got %s", c.Reason, err)
		}
	}
}

func TestESValidate(t *testing.T) {
	v, _ := NewESValidator(ES256)

	jwt := &JWT{
		Header: &Header{
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
	}

	//NOOP test
	v.validate(jwt)
}
