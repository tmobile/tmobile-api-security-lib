/*
 * Copyright 2019 Dealyze, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tmobilepoptokenbuilder

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

const key = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2ccmjG1gBJwTN
slQJAEYmQYZl0j2LI+URPXCOjWj3hcmjYQPdfd+ZeCKuA8aUgXFox1xBdIxqAnY4
8pW0MyMlwtyOiMpcnelzuKl9CqktbLSxdOUDo/wOd2d4lKnuvIHSKeoETfENroVM
3Cm3CFJ8tmpQRjMYh4MBxZh2V3XClhES8t12DI+Lznr5BWvk8oIjRRs99Xu2n9Dy
RoYal3trb+0ncdmr5EDhDE/sBC6MAk37UjyS8sty37+tbcgLkn42WISemSLnA4IO
yiW6EZHcSTXj/vUCHLJjwDyihMCUWfA6NxLPlPFcLaD4o8DEg2VOa89rL9t1SoBo
wsEhLn/5AgMBAAECggEBAI0tReOSMCpMIDpvyPliHeZShAZchsUZlJMfoO6eXGBV
Ra/ITa5iTdk7DlLrlwmplLGIu0nnPxR1LThp9xAHFiaNQBCHp1e91j124qhgzILb
AIPlOaX0igJDwWycVVboxeh0CKMmEOcOahYMs7bvmKzqlx/hAn7ztZt0ZMMGcJiO
KLIUBVOjFoCeDoLgjvNrBduvHCnQ2CcJLnBxml7oRYc63ipBeJmC+aGjCIdKGtFK
WRGiYrM4n5h4CKEnMTaZ+KAkJTmS43CBobDbp+rJbfpsGo7+xCt1VyjZfpMjF3zB
oK8LywuFDddwopcMMkCHbFo7sM9HBqW7vyzgxlBZ5QECgYEA8f6XN2o9QV57H6GO
5X0tCe5zdHt4NIHGYJfC3gVkduurMg8q/DBHBodFokp53OC48zOh6NzJOyhWacLq
H6oSLQy2oSIBIXKC3Wt9yreOa3g69tQTN+CT7OT87KMvV0nYf7lXWTxjgMLEgClh
0tDDls3+03oIQ4FpP7LBc6WhhRkCgYEAwQDmOtAYP51xuuVXl3Z0x9r6xfeIq/NG
IqlVcq6tB+yWJ+YtVoysboyTcfJbGCPRMeQlrntfHSkdjMWb8R+xwt5c0eAmcL8m
9tEtjHFa2QkqbKkQ3wRmS6KXJ8WJGY2opnVPwpWHpJn2qg01NkgQFfkjgUkWPSZx
oauKcjiwTeECfx1NtwH+22wPBNnPtn4TqmCJf3GbgfLZxCvuNKqt/HxqDVEChTIE
ppUjzErauecFT2Aj4HdSRQvk1pH4CGHNNmY+I99fPsPOGgq1+YWStKxO4tUA2VLq
3v7Qu8/r8s+fIZhV2T31EheFfkYGvNHKdeTNDQ6OuHF0Okp8WvCmHekCgYEAtfW+
GXa1Vcx/O+AbG54/bWjDgr7j6JE771PMTonmchEYY9d7qRyJONRp8kS2o2SpRqs8
52pC+wAXbu+jHMpv0jPIOMpmE2f0OUBu+/im2PXuPHGMiWXhd697aLCwmBnZBc6V
+vL05jeNuTcoktuP5tdzJOGeCNrkyLIsnZFajqECgYAGEbakt+8OpDxFVIFzPWGT
f2KIeBYHX74JiJ3C0iGYvTiIO2cPuM3sSzUfx6+kmCqKioLueMW6BcAIy0WdELOh
P1MaK10FQ12qFFrsnOZjVPoxZ4xVtzN3e4uCyc69xT2bAUpzoVKCMaCSRNv/unGk
zHNmq7/VPITL5UgtZ5nk6g==
-----END PRIVATE KEY-----
`

const encryptedKey = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,B73FCF77E44DD1F149913E43C0CE753D

BonZpgkFu6JuYaaw6iA8bwP8nQVRxnaIpBwX7DnUC3GJyib5p2/IgcPA5zgGp6s3
ji5LkQnij6BDz2ozeMmd2dqNbaefZ+jBUXAf9xXWTuu/C50Orgrh3F787WuBdXkw
/BVDRCpGwE9lheXx7agO9hXI4YQwq1Ynes9LtRLq5tpNbYvZQu2MKb4X/1esfE04
2IGdubGkAFdTcK1kiwC+oZDg+k+l2waByX71Gkcgh+YPbEMMLc6l/qxZEHrwrGPH
qe2f8/8IctZny9HPOtxQYdjItPchmCl4fikqA6vqFXcxJVduIDsiRKNhjhxlb9ip
m1G9VtPfsp1GXmIotWNpeoEyw4b8FbQjESxthnG0cN+QQbXpigtEN96ugtaPbtsA
ytrpgi0RX/Fem/E/Bp74qYVo6w+hxqWcEqyeUREROK5eNYCUEg+DsjEGs9ssqnjR
yjc4bTC1lgOGmC5B68jZ6pWe83y1t06CZHBm5DEOX3jpgESGT1t4QJr5ACwDSVx+
8yPYzX5n9XvtL7XDKIGCI3w+aRvddsvkx1PhwOZjrqyJYpTAgFAbicsnbpOGASL3
Wv6wKfUwWCyGDa6W3cLTWvnKxZJ4ctyPvjFB79a91zxMMDA16x2FbdWjoARw1Buv
R+vj0dLIZt5PgUlfLsCaZHh3aDPDljePwAguhS7ElE/gTg3xJ3xFQOow6P13ugFt
Rt7dfRa0yF9CDgjxD3g4tJUk7CGXzrQseePU69KOyVy+LV5ISm2cKJ0hNPmQ3nwL
eFaqIDmIK/LOiAnL1gLwhtLyrWzoi6igWMwbW0t97mzpdpilaaYt9jYw/yOrgy2f
QlNj7PCv0ppAGlD+74UEuxzhvnOIDVi0Rs5ck+wI1BH+BnfdJHf9xj26e6HO+Dl3
nYiswEqxFVydcOUBfGfCakJh+MMg+19ETcxRlJOl3rjNRzCD14ADqSETRZuV3NcN
ni3ReEU/G2lTsoSm3Bn5XpttgdwgUoLP2VZk6to6tf12cPR6tktH7TK3o/ANLGEK
H+ZxKSmxAnwExKatZtLkCa6XyNI3joG21bEMrJvmlLZwCQKaRh04UlzVqFDgfwU7
EUI73O80DA4kqfiKOdKIYoQCn6WSAW4bLAE44s8aebpAy7Fl8KRTdXjAlZhKlP2P
MNQTqhEjYt858AEqYGyQ5+JOUY66RG3D164llgNKHFT5RquZE4J+E4pXiWHqWBMf
+prSrqOGQGNiz2mziuDDa8myejB6yZEBACCMlUP4nZ7P5MZkOXNRvLpNro91ecL7
8frDgukb+Y3Cdf7vBYpD9GYJNITXxkzUDAWXPw0I+OPzicGCE70F2rIiic7mjp6D
FSzXjzU/lqgkgjgQhYA7gaowHtRK58M4cse781m3ZxDqNlJo6S8vkCqW9fhK7hLc
F9gGSUiIQhdh58VIEeANptXkJimxeP91Qyv3tH82iojUG9YZtGqVThquRBIrLhLP
bOXzQVxg7XxDILtdQ4oglDmHNhLzEJ2YCk3EzCdIpwZETzOMhFw1t8wGrHVZPxMi
gXyOaQpdqXxQglrWq1MRnnIe8YJo2nE+1LjA8KoDxSuqFayDXVYt/I2TdcS+H7Sa
-----END RSA PRIVATE KEY-----
`
const passphrase = "testpassphrase"

func TestNew(t *testing.T) {
	if success := t.Run("create the token builder with unencrypted key string", func(t *testing.T) {
		// Read the private key and create the token builder
		popBuilder, err := NewFromString(key, "")
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}) && t.Run("create the token builder with encrypted key string", func(t *testing.T) {
		// Read the private key and create the token builder
		popBuilder, err := NewFromString(encryptedKey, passphrase)
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}) && t.Run("create the token builder with unencrypted key bytes", func(t *testing.T) {
		// Read the private key and create the token builder
		popBuilder, err := NewFromBytes([]byte(key), "")
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}) && t.Run("create the token builder with encrypted key bytes", func(t *testing.T) {
		// Read the private key and create the token builder
		popBuilder, err := NewFromBytes([]byte(encryptedKey), passphrase)
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}) && t.Run("create the token builder with unencrypted key from file", func(t *testing.T) {
		// Write encrypted private key to disk to test loading it
		keyFile, err := ioutil.TempFile(os.TempDir(), "poptokentest")
		if err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(keyFile.Name())
		if _, err = keyFile.Write([]byte(key)); err != nil {
			t.Error(err)
			return
		}
		if err := keyFile.Close(); err != nil {
			t.Error(err)
			return
		}

		// Read the private key and create the token builder
		popBuilder, err := NewFromFile(keyFile.Name(), "")
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}) && t.Run("create the token builder with encrypted key from file", func(t *testing.T) {
		// Write encrypted private key to disk to test loading it
		keyFile, err := ioutil.TempFile(os.TempDir(), "poptokentest")
		if err != nil {
			t.Error(err)
			return
		}
		defer os.Remove(keyFile.Name())
		if _, err = keyFile.Write([]byte(encryptedKey)); err != nil {
			t.Error(err)
			return
		}
		if err := keyFile.Close(); err != nil {
			t.Error(err)
			return
		}

		// Read the private key and create the token builder
		popBuilder, err := NewFromFile(keyFile.Name(), passphrase)
		if err != nil {
			t.Error(err)
		}
		t.Log(popBuilder)
	}); !success {
		t.Fatal("tests failed")
	}
}

func TestBuild(t *testing.T) {
	var popBuilder *PoPTokenBuilder
	if success := t.Run("create the token builder", func(t *testing.T) {
		// Read the private key and create the token builder
		var err error
		popBuilder, err = NewFromString(encryptedKey, passphrase)
		if err != nil {
			t.Error(err)
		}
	}) && t.Run("build pop token POST request, no body, no query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}) && t.Run("build pop token POST request, body, no query params", func(t *testing.T) {
		// create the request
		const bodyJSON = `{"testKey": "testValue"}`
		bodyBuffer := bytes.NewBuffer([]byte(bodyJSON))
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path", bodyBuffer)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}) && t.Run("build pop token POST request, no body, query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path?some-param=testval", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}) && t.Run("build pop token POST request, body, query params", func(t *testing.T) {
		// create the request
		const bodyJSON = `{"testKey": "testValue"}`
		bodyBuffer := bytes.NewBuffer([]byte(bodyJSON))
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path?some-param=testval", bodyBuffer)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}) && t.Run("build pop token GET request, no query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("GET", "https://some.testurl.com/some/test/path", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}) && t.Run("build pop token GET request, query params", func(t *testing.T) {
		// create the request
		req, err := http.NewRequest("GET", "https://some.testurl.com/some/test/path?some-param=testval", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token
		pop, err := popBuilder.Build(req)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(pop)
	}); !success {
		t.Fatal("tests failed")
	}
}

func TestSign(t *testing.T) {
	var popBuilder *PoPTokenBuilder
	if success := t.Run("create the token builder", func(t *testing.T) {
		// Read the private key and create the token builder
		var err error
		popBuilder, err = NewFromString(encryptedKey, passphrase)
		if err != nil {
			t.Error(err)
		}
	}) && t.Run("sign pop token POST request, no body, no query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}) && t.Run("sign pop token POST request, body, no query params", func(t *testing.T) {
		// create the request
		const bodyJSON = `{"testKey": "testValue"}`
		bodyBuffer := bytes.NewBuffer([]byte(bodyJSON))
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path", bodyBuffer)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}) && t.Run("sign pop token POST request, no body, query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path?some-param=testval", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}) && t.Run("sign pop token POST request, body, query params", func(t *testing.T) {
		// create the request
		const bodyJSON = `{"testKey": "testValue"}`
		bodyBuffer := bytes.NewBuffer([]byte(bodyJSON))
		req, err := http.NewRequest("POST", "https://some.testurl.com/some/test/path?some-param=testval", bodyBuffer)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}) && t.Run("sign pop token GET request, no query params", func(t *testing.T) {
		// Create the request
		req, err := http.NewRequest("GET", "https://some.testurl.com/some/test/path", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}) && t.Run("sign pop token GET request, query params", func(t *testing.T) {
		// create the request
		req, err := http.NewRequest("GET", "https://some.testurl.com/some/test/path?some-param=testval", nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("username", "password")
		req.Header.Add("Accept", "application/json")

		// Build the PoP token and sign the request (add the "X-Authorization" header)
		if err := popBuilder.Sign(req); err != nil {
			t.Error(err)
			return
		}
		t.Log(req.Header.Get("X-Authorization"))
	}); !success {
		t.Fatal("tests failed")
	}
}
