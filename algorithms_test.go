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

func TestNoneValidate(t *testing.T) {

	nv := NoneValidator{}

	jws := &JWS{
		Header: &JWSHeader{
			Algorithm:   None,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(nil),
	}

	valid, err := nv.Validate(jws, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect NoneValidator to return an error: %s", err)
	}

	if !valid {
		t.Errorf("Expected a valid signature")
	}
}

func TestNoneSign(t *testing.T) {
	nv := NoneValidator{}

	jws := &JWS{
		Header: &JWSHeader{
			Algorithm:   None,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(nil),
	}

	err := nv.Sign(jws, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect NoneValidator.Sign to return an error: %s", err)
	}

	if len(jws.Signature) != 0 {
		t.Errorf("Invalid signature from NoneValidator. Got %#v; Expected %#v", jws.Signature, []byte(""))
	}
}

func TestHS256Validate(t *testing.T) {

	HS256V := HS256Validator{}
	b64Header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	b64Payload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	b64Signature := "Ayw1D-27S5W4XfiP-nFRm_BxSpN-v_cqlWUiwszjAB8"

	jws := &JWS{
		Header: &JWSHeader{
			Algorithm:   HS256,
			ContentType: "JWT",
			raw:         []byte(b64Header),
		},
		Payload: &Payload{
			Subject: "1234567890",
			raw:     []byte(b64Payload),
		},
		Signature: []byte(b64Signature),
	}

	valid, err := HS256V.Validate(jws, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect NoneValidator to return an error: %s", err)
	}

	if !valid {
		t.Errorf("Expected a valid signature")
	}
}

func TestHS256Sign(t *testing.T) {
	HS256V := HS256Validator{}
	b64Signature := "Ayw1D-27S5W4XfiP-nFRm_BxSpN-v_cqlWUiwszjAB8="

	jws := &JWS{
		Header: &JWSHeader{
			Algorithm:   HS256,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
		Signature: []byte(""),
	}

	err := HS256V.Sign(jws, []byte("bogokey"))

	if err != nil {
		t.Errorf("Didn't expect HS256Validator.Sign to return an error: %s", err)
	}

	if !bytes.Equal(jws.Signature, []byte(b64Signature)) {
		t.Errorf("Invalid signature from HS256Validator. Got %#v; Expected %#v", string(jws.Signature), b64Signature)
	}

	err = HS256V.Sign(jws, []byte("definitely the wrong key"))

	if err != nil {
		t.Errorf("Didn't expect HS256Validator.Sign to return an error: %s", err)
	}

	if bytes.Equal(jws.Signature, []byte(b64Signature)) {
		t.Errorf("An invalid key for HS256Validator returned an unexpected value: %#v.", jws.Signature)
	}
}
