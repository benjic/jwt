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
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const (
	ecdsaPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJT6K+Tzq3F45ulf2FPKPAI5wBOukUrRmW2N4AZ6uPytoAoGCCqGSM49
AwEHoUQDQgAE8W1MRdjuuVUWOKBMnwNKV4Hc7kQ3txFPoe6SGFQibeWJY+4RQEBr
XFduYd9OXI0eNDJna0y6k/GIoMki66bAOA==
-----END EC PRIVATE KEY-----`

	ecdsaPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8W1MRdjuuVUWOKBMnwNKV4Hc7kQ3
txFPoe6SGFQibeWJY+4RQEBrXFduYd9OXI0eNDJna0y6k/GIoMki66bAOA==
-----END PUBLIC KEY-----`
)

func TestESSign(t *testing.T) {
	var err error

	v, _ := NewESValidator(ES256)
	block, _ := pem.Decode([]byte(ecdsaPrivateKey))
	if block == nil || err != nil {
		t.Errorf("Recieved error when parisng test private key: %s\n", err)
		t.FailNow()
	}

	b64signature := "7bJGDMOLuuaLiQCJiNzJR7z6Yh8r4899Y1m6A3GdAGaY7YhMBTQX8Ahs5CHHGkrcWxKSRgrkzaTbRPFQY36BSg"

	jwt := &JWT{
		Header: &Header{
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
	}

	//NOOP test
	err = v.sign(jwt)

	if err == nil {
		t.Errorf("Expected signing with nil key to return error")
	}

	v.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
	err = v.sign(jwt)
	if err != nil {
		t.Errorf("%s", err)
	}

	if !bytes.Equal(jwt.Signature, []byte(b64signature)) {
		t.Errorf("Recieved unexpected signature:\nwant: %s\n got: %s\n", b64signature, string(jwt.Signature))
	}
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
