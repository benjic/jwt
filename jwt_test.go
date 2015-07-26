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
	validjwsToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
)

type TestPayload struct {
	Name string `json:"name"`
}

func TestJWTToken(t *testing.T) {
	decoder := NewJWSDecoder(bytes.NewBufferString(validjwsToken))
	payload := new(TestPayload)

	err := decoder.Decode(payload)

	if err != nil {
		t.Errorf("Expected valid JWTtoken to not throw error. Got error: %s", err)
	}

	if payload.Name != "John Doe" {
		t.Errorf("Invalid name from payload: %s", payload.Name)
	}
}
