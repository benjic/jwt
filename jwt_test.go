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

const (
	generatedJWTToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJzdWIiOiIxMjM0NTY3ODkwIiwiQWRtaW4iOnRydWUsIlVzZXJJRCI6MTIzNH0.zFYZZKQzJ5ExEbFCVl5gk1efdv3S9ZQlGHBVCqko9xc"
)

type TestPayload struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		Reason        string
		Token         string
		ExpectedError error
	}{
		{
			"the token is a missing fields",
			"abc.def",
			ErrMalformedToken,
		},
		{
			"header is not valid base64",
			"notvalidbase64.e30k.YQo=",
			ErrMalformedToken,
		},
		{
			"payload is not valid base64",
			"eyJhbGciOiJub25lIn0K.notvalidb64.YQo=",
			ErrMalformedToken,
		},
		{
			"header is not valid JSON",
			"YQo=.e30k.YQo=",
			ErrMalformedToken,
		},
		{
			"payload is not valid JSON",
			"eyJhbGciOiJub25lIn0K.YQo=.YQo=",
			ErrMalformedToken,
		},
		{
			"The signature is not valid b64 string",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30k.badBase64",
			ErrMalformedToken,
		},
		{
			"the algorithm in header is not supported",
			"eyJhbGciOiJ1bmtub3duIiwidHlwIjoiSldUIn0.e30k.YQo=",
			ErrAlgorithmNotImplemented,
		},
		{
			"The signature is incorrect",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30k.YQo=",
			ErrBadSignature,
		},
	}

	for _, c := range cases {
		decoder := NewDecoder(bytes.NewBufferString(c.Token), []byte("secret"))
		payload := new(TestPayload)

		err := decoder.Decode(payload)

		if err != c.ExpectedError {
			t.Errorf("Expected %s error when %s; got %s", c.ExpectedError, c.Reason, err)

		}
	}
}

func TestDecodingValidators(t *testing.T) {
	cases := []struct {
		Reason    string
		Token     string
		Algorithm Algorithm
	}{
		{
			"hs256 is supported",
			"eyJhbGciOiJIUzI1NiJ9Cg==.e30k.Yqo=",
			HS256,
		},
		{
			"none is supported",
			"eyJhbGciOiJub25lIn0K.e30k.Yqo=",
			None,
		},
	}

	for _, c := range cases {
		decoder := NewDecoder(bytes.NewBufferString(c.Token), []byte("secret"))
		payload := new(TestPayload)

		err := decoder.Decode(payload)

		if err == ErrAlgorithmNotImplemented {
			t.Errorf("Confirm %s, recieved %s", c.Reason, err)

		}
	}
}

func TestMalformedToken(t *testing.T) {
	malformedTokens := []string{"adfasdf.asd", ""}
	badBase64Tokens := []string{"not.base.64", "======.23.23", "abc.badpaylod.abc"}

	for _, badJWT := range malformedTokens {
		decoder := NewDecoder(bytes.NewBufferString(badJWT), []byte("secret"))
		payload := new(TestPayload)

		err := decoder.Decode(payload)

		if err != ErrMalformedToken {
			t.Errorf("Expected %s to error as ErrMalformedToken; got %+v", badJWT, err)
		}
	}

	for _, badJWT := range badBase64Tokens {
		decoder := NewDecoder(bytes.NewBufferString(badJWT), []byte("secret"))
		payload := new(TestPayload)

		err := decoder.Decode(payload)

		if err == nil {
			t.Errorf("Expected %s to error as CorruptInputError; got %+v", badJWT, err)
		}
	}
}

func TestEncoder(t *testing.T) {

	payload := struct {
		Payload
		Admin  bool
		UserID int
	}{
		Payload{Subject: "1234567890", Issuer: "Ben Campbell"},
		true,
		1234,
	}

	buf := bytes.NewBuffer(nil)
	enc := NewEncoder(buf, []byte("bogokey"))

	if err := enc.Encode(payload, HS256); err != nil {
		t.Errorf("Got error encoding token: %s", err)
	}

	if buf.String() != generatedJWTToken {
		t.Errorf("Invalid Token:\n%s\n%s", buf.String(), generatedJWTToken)
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
