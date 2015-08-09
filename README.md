# jwt

> JSON Web Tokens are an open, industry standard [RFC 7519][0] method for
> representing claims securely between two parties.

The best way to understand how something functions is by taking it apart and putting it back together. This is a exploration in
implementing a simple and concise encoder/decoder library for JWT.

[![Build Status](https://travis-ci.org/benjic/jwt.svg?branch=master)](https://travis-ci.org/benjic/jwt)
[![GoDoc](https://godoc.org/github.com/benjic/jwt?status.svg)](https://godoc.org/github.com/benjic/jwt)
[![Coverage Status](https://coveralls.io/repos/benjic/jwt/badge.svg?branch=master&service=github)](https://coveralls.io/github/benjic/jwt?branch=master)

## Library Features

|              |  Feature  |              | Algorithm |
|--------------|-----------|--------------|-----------|
|     :+1:     | Sign      |     :+1:     |   HS256   |
|     :+1:     | Verify    |     :+1:     |   HS384   |
| :red_circle: | iss check |     :+1:     |   HS512   |
| :red_circle: | sub check |     :+1:     |   RS256   |
| :red_circle: | aud check |     :+1:     |   RS384   |
| :red_circle: | exp check |     :+1:     |   RS512   |
| :red_circle: | nbf check | :red_circle: |   ES256   |
| :red_circle: | iat check | :red_circle: |   ES384   |
| :red_circle: | jti check | :red_circle: |   ES512   |

## Examples

### [Create token](http://godoc.com/github.com/benjic/jwt/#Encoder)

```go
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
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI
}
```

### [Consume a token](http://godoc.com/github.com/benjic/jwt/#Decoder)
```go
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJCZW4gQ2FtcGJlbGwiLCJhZG1pbiI6dHJ1ZSwidXNlcl9pZCI6MTIzNH0.r4W8qDl8i8cUcRUxtA3hM0SZsLScHiBgBKZc_n_GrXI"

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
	// Output: &{Payload:{Issuer:Ben Campbell Subject: Audience: ExpirationTime:<nil> NotBefore:<nil> IssuedAt:<nil> JWTId: raw:[]} Admin:true UserID:1234}
```

#### References
- [JWT Homepage][1]
- [JWT Standard][0]

[0]: https://tools.ietf.org/html/rfc7519
[1]: http://jwt.io/
