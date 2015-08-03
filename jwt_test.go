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
	"fmt"
	"testing"
)

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		ExpectedError error
		Reason        string
		Token         string
	}{
		{ErrMalformedToken, "no fields at all!", ""},
		{ErrMalformedToken, "the token is a missing fields", "abc.def"},
		{ErrMalformedToken, "header is not valid base64", "======.e30k.YQo="},
		{ErrMalformedToken, "payload is not valid base64", "eyJhbGciOiJub25lIn0K.======.YQo="},
		{ErrMalformedToken, "The signature is not valid b64 string", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30k.badBase64"},
		{ErrMalformedToken, "header is not valid JSON", "YQo=.e30k.YQo="},
		{ErrMalformedToken, "payload is not valid JSON", "eyJhbGciOiJub25lIn0K.YQo=.YQo="},
		{ErrAlgorithmNotImplemented, "the algorithm in header is not supported", "eyJhbGciOiJ1bmtub3duIiwidHlwIjoiSldUIn0.e30k.YQo="},
		{ErrBadSignature, "The signature is incorrect", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30k.YQo="},
	}

	for _, c := range cases {
		decoder := NewDecoder(bytes.NewBufferString(c.Token), []byte("secret"))
		payload := &struct{}{}

		err := decoder.Decode(payload)

		if err != c.ExpectedError {
			t.Errorf("Expected %s error when %s; got %s", c.ExpectedError, c.Reason, err)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	cases := []struct {
		ExpectedError error
		Reason        string
		Payload       interface{}
		Algorithm     Algorithm
	}{
		{ErrAlgorithmNotImplemented, "using an unsupported algorithm", struct{ IsAdmin bool }{false}, "bogoAlgorithm"},
	}

	for _, c := range cases {
		buf := bytes.NewBuffer(nil)
		enc := NewEncoder(buf, []byte("bogokey"))

		if err := enc.Encode(c.Payload, c.Algorithm); err != c.ExpectedError {
			t.Errorf("Expected %s error when %s; got %s", c.ExpectedError, c.Reason, err)
		}
	}
}

func TestDecodingValidating(t *testing.T) {
	cases := []struct {
		Algorithm Algorithm
		Token     string
		Key       []byte
	}{
		{
			HS256,
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.UGgJ_8f7TlqazSojqRAKzMJ0SUWJCJJ_9jDHe5nrhto",
			[]byte("bogokey"),
		},
		{
			HS384,
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.UGgJ_8f7TlqazSojqRAKzMJ0SUWJCJJ_9jDHe5nrhto",
			[]byte("bogokey"),
		},
		{
			HS512,
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.UGgJ_8f7TlqazSojqRAKzMJ0SUWJCJJ_9jDHe5nrhto",
			[]byte("bogokey"),
		},
		{
			None,
			"eyJhbGciOiJub25lIn0K.e30k.",
			[]byte(nil),
		},
	}

	for _, c := range cases {
		decoder := NewDecoder(bytes.NewBufferString(c.Token), c.Key)
		payload := &struct{}{}

		err := decoder.Decode(payload)

		if err != nil {
			t.Errorf("Confirm %s is supported and valid; recieved %s", c.Algorithm, err)
		}
	}
}

func TestEncodingSigning(t *testing.T) {
	cases := []struct {
		Algorithm  Algorithm
		Payload    interface{}
		ValidToken string
	}{

		{HS256, struct{}{}, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.UGgJ_8f7TlqazSojqRAKzMJ0SUWJCJJ_9jDHe5nrhto"},
		{HS384, struct{}{}, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.YGfeZ7CN9vKz4M2SINxTixlpUEDqsCZNx4LMJK62Lr_Eiptnikcf5XfgDd_7eVWe"},
		{HS512, struct{}{}, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.wHUM-6oRBExIgOk9MLOQ_80WqbuOmXXNuyTy4WmM_0WBM6pXld0mru8rZbc9-E314K9UhMkDNHbg2MRjIsCR3g"},
	}

	for _, c := range cases {
		buf := bytes.NewBuffer(nil)
		enc := NewEncoder(buf, []byte("bogokey"))

		if err := enc.Encode(c.Payload, c.Algorithm); err != nil {
			t.Errorf("Confirm %s is a supported algorithm, recieved %s", c.Algorithm, err)
		}

		if buf.String() != c.ValidToken {
			t.Errorf("Confirm %s correctly generates a valid token\nExpected: %s\nGot: %s\n", c.Algorithm, c.ValidToken, buf.String())
		}
	}
}

func ExampleEncoder() {
	payload := &struct {
		Payload
		Admin  bool `json:"admin"`
		UserID int  `json:"user_id"`
	}{
		Payload: Payload{Issuer: "Ben Campbell"},
		Admin:   true,
		UserID:  1234,
	}
	tokenBuffer := bytes.NewBuffer(nil)
	err := NewEncoder(tokenBuffer, []byte("bogokey")).Encode(payload, HS256)

	if err != nil {
		panic(err)
	}

	fmt.Println(tokenBuffer.String())
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI
}

func ExampleDecoder() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI"

	payload := &struct {
		Payload
		Admin  bool `json:"admin"`
		UserID int  `json:"user_id"`
	}{}

	err := NewDecoder(bytes.NewBufferString(token), []byte("bogokey")).Decode(payload)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", payload)
	// Output: &{Payload:{Issuer:Ben Campbell Subject: Audience: ExpirationTime:<nil> NotBefore:<nil> IssuedAt:<nil> JWTId: raw:[]} Admin:true UserID:1234}
}
