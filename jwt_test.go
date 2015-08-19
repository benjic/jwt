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
	"errors"
	"fmt"
	"testing"
)

var ErrTestValidator = errors.New("A fake validator error")

type TestValidator struct{}

func (v TestValidator) sign(jwt *jwt) error             { return ErrTestValidator }
func (v TestValidator) validate(jwt *jwt) (bool, error) { return false, ErrTestValidator }

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

	v := NewHSValidator(HS256)
	v.Key = []byte("bogokey")

	for _, c := range cases {
		decoder := NewDecoder(bytes.NewBufferString(c.Token), v)
		payload := &struct{}{}

		err := decoder.Decode(payload)

		if err != c.ExpectedError {
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
			"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.YGfeZ7CN9vKz4M2SINxTixlpUEDqsCZNx4LMJK62Lr_Eiptnikcf5XfgDd_7eVWe",
			[]byte("bogokey"),
		},
		{
			HS512,
			"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.wHUM-6oRBExIgOk9MLOQ_80WqbuOmXXNuyTy4WmM_0WBM6pXld0mru8rZbc9-E314K9UhMkDNHbg2MRjIsCR3g",
			[]byte("bogokey"),
		},
		{
			None,
			"eyJhbGciOiJub25lIn0K.e30k.",
			[]byte(nil),
		},
	}

	for _, c := range cases {
		var decoder *Decoder

		switch c.Algorithm {
		case HS256, HS384, HS512:
			v := NewHSValidator(c.Algorithm)
			v.Key = c.Key
			decoder = NewDecoder(bytes.NewBufferString(c.Token), v)
		case None:
			v := nonevalidator{}
			decoder = NewDecoder(bytes.NewBufferString(c.Token), v)
		}

		payload := &struct{}{}
		err := decoder.Decode(payload)

		if err != nil {
			t.Errorf("Confirm %s is supported and valid; recieved %s", c.Algorithm, err)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	cases := []struct {
		expectedError error
		validator     Validator
	}{
		{ErrTestValidator, TestValidator{}},
	}

	for _, c := range cases {
		buf := bytes.NewBuffer(nil)
		enc := NewEncoder(buf, c.validator)

		if err := enc.Encode(&struct{}{}); err != c.expectedError {
			t.Errorf("Expected %s error when encoding, recieved %s", c.expectedError, err)
		}
	}
}

func TestEncodingSigning(t *testing.T) {
	cases := []struct {
		Algorithm  Algorithm
		Payload    interface{}
		ValidToken string
	}{
		{HS256, struct{}{}, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.UGgJ_8f7TlqazSojqRAKzMJ0SUWJCJJ_9jDHe5nrhto="},
		{HS384, struct{}{}, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.YGfeZ7CN9vKz4M2SINxTixlpUEDqsCZNx4LMJK62Lr_Eiptnikcf5XfgDd_7eVWe"},
		{HS512, struct{}{}, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.wHUM-6oRBExIgOk9MLOQ_80WqbuOmXXNuyTy4WmM_0WBM6pXld0mru8rZbc9-E314K9UhMkDNHbg2MRjIsCR3g=="},
	}

	for _, c := range cases {
		buf := bytes.NewBuffer(nil)

		v := NewHSValidator(c.Algorithm)
		v.Key = []byte("bogokey")

		enc := NewEncoder(buf, v)

		if err := enc.Encode(c.Payload); err != nil {
			t.Errorf("Confirm %s is a supported algorithm, recieved %s", c.Algorithm, err)
		}

		if buf.String() != c.ValidToken {
			t.Errorf("Confirm %s correctly generates a valid token\nExpected:\t%s\nGot:\t\t%s\n", c.Algorithm, c.ValidToken, buf.String())
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

	v := NewHSValidator(HS256)
	v.Key = []byte("bogokey")

	err := NewEncoder(tokenBuffer, v).Encode(payload)

	if err != nil {
		panic(err)
	}

	fmt.Println(tokenBuffer.String())
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI=
}

func ExampleDecoder() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI="

	payload := &struct {
		Payload
		Admin  bool `json:"admin"`
		UserID int  `json:"user_id"`
	}{}

	v := NewHSValidator(HS256)
	v.Key = []byte("bogokey")

	err := NewDecoder(bytes.NewBufferString(token), v).Decode(payload)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", payload)
	// Output: &{Payload:{Issuer:Ben Campbell Subject: Audience: ExpirationTime:<nil> NotBefore:<nil> IssuedAt:<nil> JWTId:} Admin:true UserID:1234}
}
