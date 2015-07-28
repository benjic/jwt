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

const (
	validJWSToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	generatedJWSToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJzdWIiOiIxMjM0NTY3ODkwIn0=.PJ5rUFTxZU5_qAS0yI5jdmoMHAD-lio-ZiNh2qOQqj0="
)

type TestPayload struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

type RegisteredClaimPayload struct {
	Payload
	Name string `json:"name"`
}

func TestJWTToken(t *testing.T) {
	decoder := NewJWSDecoder(bytes.NewBufferString(validJWSToken), []byte("secret"))
	payload := new(TestPayload)

	err := decoder.Decode(payload)

	if err != nil {
		t.Errorf("Expected valid JWTtoken to not throw error. Got error: %s", err)
	}

	if payload.Name != "John Doe" {
		t.Errorf("Invalid name from payload: %s", payload.Name)
	}

	if !payload.Admin {
		t.Errorf("Invalid admin claim, expected %t got %t", true, payload.Admin)
	}
}

func TestRegisteredClaims(t *testing.T) {
	decoder := NewJWSDecoder(bytes.NewBufferString(validJWSToken), []byte("secret"))
	payload := new(RegisteredClaimPayload)

	if err := decoder.Decode(payload); err != nil {
		t.Errorf("Expected validJWSToken to not throw error, got: %s", err)
	}

	if payload.Subject != "1234567890" {
		t.Errorf("Expected Registered Claim \"sub\": 1234567890, got %s", payload.Subject)
	}
}

func TestJWSEncoder(t *testing.T) {

	payload := &Payload{Subject: "1234567890", Issuer: "Ben Campbell"}

	buf := bytes.NewBuffer(nil)
	enc := NewJWSEncoder(buf, []byte("bogokey"))

	if err := enc.Encode(payload, HS256); err != nil {
		t.Errorf("Got error encoding token: %s", err)
	}

	if buf.String() != generatedJWSToken {
		t.Errorf("Invalid Token:\n%s\n%s", buf.String(), generatedJWSToken)
	}
}
