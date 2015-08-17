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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const (
	ecdsa256PrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJT6K+Tzq3F45ulf2FPKPAI5wBOukUrRmW2N4AZ6uPytoAoGCCqGSM49
AwEHoUQDQgAE8W1MRdjuuVUWOKBMnwNKV4Hc7kQ3txFPoe6SGFQibeWJY+4RQEBr
XFduYd9OXI0eNDJna0y6k/GIoMki66bAOA==
-----END EC PRIVATE KEY-----`

	ecdsa256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8W1MRdjuuVUWOKBMnwNKV4Hc7kQ3
txFPoe6SGFQibeWJY+4RQEBrXFduYd9OXI0eNDJna0y6k/GIoMki66bAOA==
-----END PUBLIC KEY-----`
)

type nullReader struct{}

func (r nullReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(0)
	}
	return len(p), nil
}

func TestESSign(t *testing.T) {
	var err error

	v, _ := NewESValidator(ES256)
	v.rand = nullReader{}

	block, _ := pem.Decode([]byte(ecdsa256PrivateKey))
	if block == nil || err != nil {
		t.Errorf("Recieved error when parisng test private key: %s\n", err)
		t.FailNow()
	}

	b64signature := "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY1q7OQwkG30-DAgdLFcbXyCnpXQNucJwr1oF-m0ri0ZA=="
	jwt := &JWT{
		Header: &Header{
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
	}

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
		{None, ErrAlgorithmNotImplemented, "did not expect to get a valid ES validator"},
		{ES256, nil, "did not expect to get a valid ES validator"},
		{ES384, nil, "did not expect to get a valid ES validator"},
		{ES512, nil, "did not expect to get a valid ES validator"},
	}

	for _, c := range cases {
		v, err := NewESValidator(c.Algorithm)

		if err != c.ExpectedError {
			t.Errorf("%s: got %s", c.Reason, err)
		}

		if v.algorithm != c.Algorithm {
			t.Errorf("Expected algorithm returned by NewESValidator to be %s, got %s", c.Algorithm, v.algorithm)
		}
	}
}

func TestESValidate(t *testing.T) {
	ES256V, _ := NewESValidator(ES256)
	block, _ := pem.Decode([]byte(ecdsa256PublicKey))
	if block == nil {
		t.Error("Unable to parse block from pem\n")
		t.FailNow()
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		t.Errorf("Recieved error when parisng test public key: %s\n", err)
		t.FailNow()
	}

	b64Header := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
	b64Payload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	b64Signature := "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY1q7OQwkG30-DAgdLFcbXyCnpXQNucJwr1oF-m0ri0ZA=="

	JWT := &JWT{
		Header: &Header{
			Algorithm:   ES256,
			ContentType: "JWT",
		},
		headerRaw: []byte(b64Header),
		Payload: &Payload{
			Subject: "1234567890",
		},
		payloadRaw: []byte(b64Payload),
	}

	valid, err := ES256V.validate(JWT)

	if valid || err == nil {
		t.Error("Expected a nil public key pointer to return invalid")
	}

	ES256V.PublicKey = pubKey.(*ecdsa.PublicKey)
	JWT.Signature = []byte("invalid base64 string")
	valid, err = ES256V.validate(JWT)

	if valid || err == nil {
		t.Error("Expected validate to return invalid signature and error when using bad base64 signature")
	}

	JWT.Signature = []byte("YmFkIHNpZ25hdHVyZQo=")

	valid, err = ES256V.validate(JWT)

	if valid || err != nil {
		if err != nil {
			t.Errorf("Did not expect esvalidator to return an error with a properly formated signature: %s", err)
		}

		t.Errorf("Expectd to find an invalid siganture")
	}

	JWT.Signature = []byte(b64Signature)
	valid, err = ES256V.validate(JWT)

	if !valid || err != nil {
		if err != nil {
			t.Errorf("Did not expect esvalidator to return an error with a properly formated signature: %s", err)
		}

		t.Errorf("Expected to find valid siganture")
	}

}
