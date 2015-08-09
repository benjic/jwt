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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const privateKey string = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzIIdoS0tocpJxSLYfS1RnBVAsSjLjjUtLXahPuo3NmvuEPc6
mEseT73aKUHiq8Twio6oiwFGWcsy+da5Ta17aTfMzVNxG4DJvocdGEr+YO/EKm+d
eURjOEcZ3rW+bHPc2HnTkMqpWQ10jIBu91RaYmyWpvnz9oOW6st8MVSNMJKPBowR
lvMDKMqmsyX13nTvmQN3m/OqE6o8gYhj0mvP+U4sJ0bc/LgAWed54b1AWLlh6NML
K3wSWP0Ve5oIQnIzR4wwtptonZ9SNtWVKL3EZhX0/DjL/1qd8aXzjFn1ivFUEB7E
SSaNjFOrk/64TN00uwizXbbtc76Ttd6MnOfTYwIDAQABAoIBAQCaHlCP/4kNDXKM
sxbtNvLyqn2HRRQqBl8WjPk1fbLAO5Q8iuRIkwuz0oKPZwyYoCEaeioAH6TR1LWE
3NHm/R8tCxU3g3OQ43ymLhK6FQIhMW/m/xhwpB4V8ldHpDVua9558U2EJ4Z6Cw7T
N5Lop1Q6KlVaXrIBC+f26ASe9HY2rFLBWtG2IS26f2P6zjdl5MDrumvmHGTIk8Jf
KvoOnJ5fWK52K57GJEA+ZP1b9Qf5D1HeFhi2P5sp/8ivFl6zKe2h9Lu7pOTqLz6o
9XcqFY95y+TcmaTuGyyrIyrrcluPF6Zh5OrTVEMv3uso6MK8nWRwYDCMjUjHmBkI
rTsJRLeJAoGBAPNRJhRHjWUIlIrE3nlsHsbxZC8rkvzSyIh5vH7RWYiuhOgTtkQn
7dV2d/xoSOIn6YU6LC+k++D7z0BtD/3MKUZyz+b2k5STrGJdDjaZ3S2+hceO9889
CPLPszqvURk0wEtEPFeEAWKWCzGfgu/lTvu1dS4LQc+FznFyOhmdT3JNAoGBANcr
GUVBUyJ2n0l3JPLOwTYXucg57ilqUygOAm1j71fFKM5mWkvusigDdPxaPl+Znhoz
gZR5vi72AUHVxWArxrnRMYF5aNTjdjtTAuOXQ+9HBti7zgSiQ8NDvo6DKMOdcM7G
xv8AUAQMzd6XKGvGuehcHoXXfnSgaqeGHgqfxFRvAoGAY/tqfFbSoTufXk57ZMWq
9/DlTATJx54NzRbJAAuikOm1r2+6K9OEhXzC3TM1D8l6ycYXthRDdDXE+iJWueGU
7F/tUmjsR9dOtLSsTH95RXzOmCwFZGEeNjhm26yC1Kq6gbMuYH/b2djyDJgRQ+ak
SAZOenchudav+CoJ+dCMftkCgYBvglp6Vbxr4+XxANoZK6VeDzWs2rjepceqvnfr
kRr89aSMMucg6vdRXVlHXs1sZgRVt9OzytQRKlTEdbDwgj9fFVb+rpjxm2Aupnqc
0EvYuYqGz+2Y4S8VBwq+eKKrnfBUeRewF81gC/K1JMlB8Z9vGC6JVoCmmGwtnYf8
IYhx6QKBgBkSg6Gg+fVXgwmHUgrRKSgYEmFVo1oZ4Xq2zdbYbiIL+JM5o2W0wq59
42tO/Fq3GPKuIzIZPFMuCboqK8wY6n3Tkox2Mkn1QKUV/Aqtd21g3goil8uycXun
7WFocvEp7a7UHVKH0ArP4K6INgxb7+Xd9kdXvbH8wITFJD1Eu/jP
-----END RSA PRIVATE KEY-----`

const publicKey string = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIIdoS0tocpJxSLYfS1R
nBVAsSjLjjUtLXahPuo3NmvuEPc6mEseT73aKUHiq8Twio6oiwFGWcsy+da5Ta17
aTfMzVNxG4DJvocdGEr+YO/EKm+deURjOEcZ3rW+bHPc2HnTkMqpWQ10jIBu91Ra
YmyWpvnz9oOW6st8MVSNMJKPBowRlvMDKMqmsyX13nTvmQN3m/OqE6o8gYhj0mvP
+U4sJ0bc/LgAWed54b1AWLlh6NMLK3wSWP0Ve5oIQnIzR4wwtptonZ9SNtWVKL3E
ZhX0/DjL/1qd8aXzjFn1ivFUEB7ESSaNjFOrk/64TN00uwizXbbtc76Ttd6MnOfT
YwIDAQAB
-----END PUBLIC KEY-----`

func TestRSValidate(t *testing.T) {
	RS256V := NewRSValidator(RS256)
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		t.Error("Unable to parse block from pem\n")
		t.FailNow()
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		t.Errorf("Recieved error when parisng test private key: %s\n", err)
		t.FailNow()
	}

	b64Header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	b64Payload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	b64Signature := "e-mU_hjtyUkDZfe63d-WN2YlTXJkMdaR04sbORQQGKFtLYSvVVknU8rbhlGq4eWCCFnYgK9_vJ37DpIV-OBLZ1JoWvmdh1oIHJsY9PJLhw4fK6Hq20Vfde-AkCWQT3I4r93Ymc3J-sRUGrDeKLmnbWnPeC6TQS7f8vjLHnCcvOFNK7BmJadhRDfI3Wxh988KP71v9I6lSlN_zWXPbdlFljBQzF0bpyDgidCqr2EqeJpnBBeE_0Bs7J1d34N0jyEs6P5aMsoIlI07bl_zoEJ2aYWuUNR9qbyK1K-OpAGG7X7l4qLmPP1HdQmHO9JkchShLgj8soDgnZBaFAm1Us_nwA=="

	JWT := &JWT{
		Header: &Header{
			Algorithm:   RS256,
			ContentType: "JWT",
		},
		headerRaw: []byte(b64Header),
		Payload: &Payload{
			Subject: "1234567890",
		},
		payloadRaw: []byte(b64Payload),
	}

	valid, err := RS256V.validate(JWT)

	if valid || err == nil {
		t.Error("Expected a nil public key pointer to return invalid")
	}

	RS256V.PublicKey = pubKey.(*rsa.PublicKey)
	JWT.Signature = []byte("invalid base64 string")
	valid, err = RS256V.validate(JWT)

	if valid || err == nil {
		t.Error("Expected validate to return invalid signature and error when using bad base64 signature")
	}

	JWT.Signature = []byte(b64Signature)
	valid, err = RS256V.validate(JWT)

	if !valid || err != nil {
		if err != nil {
			t.Errorf("Didn't expect rsvalidator to return an error: %s", err)
		}
		t.Errorf("Expectd to find valid siganture")
	}

	JWT.Signature = []byte("YmFkIHNpZ25hdHVyZQo=")

	valid, err = RS256V.validate(JWT)

	if valid || err == nil {
		if err == nil {
			t.Errorf("Didn't expect rsvalidator to return an error: %s", err)
		}
		t.Errorf("Expectd to find valid siganture")
	}

}

func TestRSSign(t *testing.T) {
	var err error

	RS256V := NewRSValidator(RS256)
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		t.Errorf("Recieved error when parisng test private key: %s\n", err)
		t.FailNow()
	}

	RS256V.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Recieved error when parisng test private key: %s\n", err)
		t.FailNow()
	}

	b64Signature := "e-mU_hjtyUkDZfe63d-WN2YlTXJkMdaR04sbORQQGKFtLYSvVVknU8rbhlGq4eWCCFnYgK9_vJ37DpIV-OBLZ1JoWvmdh1oIHJsY9PJLhw4fK6Hq20Vfde-AkCWQT3I4r93Ymc3J-sRUGrDeKLmnbWnPeC6TQS7f8vjLHnCcvOFNK7BmJadhRDfI3Wxh988KP71v9I6lSlN_zWXPbdlFljBQzF0bpyDgidCqr2EqeJpnBBeE_0Bs7J1d34N0jyEs6P5aMsoIlI07bl_zoEJ2aYWuUNR9qbyK1K-OpAGG7X7l4qLmPP1HdQmHO9JkchShLgj8soDgnZBaFAm1Us_nwA"
	JWT := &JWT{
		Header: &Header{
			Algorithm:   RS256,
			ContentType: "JWT",
		},
		Payload: &Payload{
			Subject: "1234567890",
		},
	}

	err = RS256V.sign(JWT)

	if err != nil {
		t.Errorf("Didn't expect rs256validator.Sign to return an error: %s", err)
	}

	if !bytes.Equal(JWT.Signature, []byte(b64Signature)) {
		t.Errorf("Invalid signature from rs256validator. Got %#v; Expected %#v", string(JWT.Signature), b64Signature)
	}

	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error("Error generating new key")
	}

	RS256V.PrivateKey = badKey
	err = RS256V.sign(JWT)

	if err != nil {
		t.Errorf("Didn't expect hs256validator.Sign to return an error: %s", err)
	}

	if bytes.Equal(JWT.Signature, []byte(b64Signature)) {
		t.Errorf("An invalid key for hs256validator returned an unexpected value: %#v.", JWT.Signature)
	}
}
