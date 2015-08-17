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

func TestNonevalidate(t *testing.T) {

	nv := nonevalidator{}

	JWT := &JWT{
		Header: &Header{
			Algorithm:   None,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(nil),
	}

	valid, err := nv.validate(JWT)

	if err != nil {
		t.Errorf("Didn't expect nonevalidator to return an error: %s", err)
	}

	if !valid {
		t.Errorf("Expected a valid signature")
	}
}

func TestNonesign(t *testing.T) {
	nv := nonevalidator{}

	JWT := &JWT{
		Header: &Header{
			Algorithm:   None,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(nil),
	}

	err := nv.sign(JWT)

	if err != nil {
		t.Errorf("Didn't expect nonevalidator.Sign to return an error: %s", err)
	}

	if len(JWT.Signature) != 0 {
		t.Errorf("Invalid signature from nonevalidator. Got %#v; Expected %#v", JWT.Signature, []byte(""))
	}
}
