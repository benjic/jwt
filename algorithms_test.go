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
	"testing"
)

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

	valid, err := nv.validate(JWT, []byte("bogokey"))

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

	err := nv.sign(JWT, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect nonevalidator.Sign to return an error: %s", err)
	}

	if len(JWT.Signature) != 0 {
		t.Errorf("Invalid signature from nonevalidator. Got %#v; Expected %#v", JWT.Signature, []byte(""))
	}
}

func TestHS256validate(t *testing.T) {

	HS256V := hs256validator{}
	b64Header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	b64Payload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	b64Signature := "Ayw1D-27S5W4XfiP-nFRm_BxSpN-v_cqlWUiwszjAB8"

	JWT := &JWT{
		Header: &Header{
			Algorithm:   HS256,
			ContentType: "JWT",
		},
		headerRaw: []byte(b64Header),
		Payload: &Payload{
			Subject: "1234567890",
		},
		payloadRaw: []byte(b64Payload),
		Signature:  []byte(b64Signature),
	}

	valid, err := HS256V.validate(JWT, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect nonevalidator to return an error: %s", err)
	}

	if !valid {
		t.Errorf("Expected a valid signature")
	}
}

func TestHS256sign(t *testing.T) {
	HS256V := hs256validator{}
	b64Signature := "Ayw1D-27S5W4XfiP-nFRm_BxSpN-v_cqlWUiwszjAB8="

	JWT := &JWT{
		Header: &Header{
			Algorithm:   HS256,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(""),
	}

	err := HS256V.sign(JWT, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect hs256validator.Sign to return an error: %s", err)
	}

	if !bytes.Equal(JWT.Signature, []byte(b64Signature)) {
		t.Errorf("Invalid signature from hs256validator. Got %#v; Expected %#v", string(JWT.Signature), b64Signature)
	}

	err = HS256V.sign(JWT, []byte("definitely the wrong key"))

	if err != nil {
		t.Errorf("Didn't expect hs256validator.Sign to return an error: %s", err)
	}

	if bytes.Equal(JWT.Signature, []byte(b64Signature)) {
		t.Errorf("An invalid key for hs256validator returned an unexpected value: %#v.", JWT.Signature)
	}
}
