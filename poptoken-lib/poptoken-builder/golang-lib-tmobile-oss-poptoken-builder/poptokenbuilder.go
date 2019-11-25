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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

const debug = false

func debugLog(format string, a ...interface{}) (n int, err error) {
	if debug {
		return fmt.Printf(format, a...)
	}
	return 0, nil
}

// PoPTokenBuilder - generates and signs a T-Mobile PoP token for API requests
type PoPTokenBuilder struct {
	privateKey *rsa.PrivateKey
}

// NewFromBytes - returns a PoPTokenBuilder using a PEM formatted RSA private key byte array
func NewFromBytes(key []byte, passphrase string) (*PoPTokenBuilder, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("Must pass a PEM formatted RSA private key byte array")
	}

	if passphrase == "" {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			return nil, err
		}
		return &PoPTokenBuilder{privateKey: privateKey}, nil
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(key, passphrase)
	if err != nil {
		return nil, err
	}
	return &PoPTokenBuilder{privateKey: privateKey}, nil
}

// NewFromString - returns a PoPTokenBuilder using a PEM formatted RSA private key string
func NewFromString(key string, passphrase string) (*PoPTokenBuilder, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("Must pass a PEM formatted RSA private key string")
	}

	return NewFromBytes([]byte(key), passphrase)
}

// NewFromFile - returns a PoPTokenBuilder using a PEM formatted RSA private key loaded from a file
func NewFromFile(path string, passphrase string) (*PoPTokenBuilder, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("Must pass in a path to a PEM formatted RSA private key")
	}

	// Read the private key PEM file from disk
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return NewFromBytes(key, passphrase)
}

// buildEHTSAndEDTS - builds the contatenated and hashed ehts and edts strings
func buildEHTSAndEDTS(r *http.Request) (ehts string, edts string, err error) {
	var keysBuilder strings.Builder
	var valuesBuilder strings.Builder

	// Loop through all headers to create the ehts string (concatenated keys)
	// and edts string (concatenated values)
	for k, v := range r.Header {
		// Handle the edge case of multiple instances of the same header by looping the header values
		for _, hv := range v {
			keysBuilder.WriteString(k)
			keysBuilder.WriteString(";")
			valuesBuilder.WriteString(hv)
			debugLog("ehts key: %s  edts value: %s\n", k, hv)
		}
	}

	// Add the additional non-header values
	// uri
	keysBuilder.WriteString("uri")
	keysBuilder.WriteString(";")
	valuesBuilder.WriteString(r.URL.RequestURI())
	debugLog("ehts key: %s  edts value: %s\n", "uri", r.URL.RequestURI())
	// http-method
	keysBuilder.WriteString("http-method")
	valuesBuilder.WriteString(r.Method)
	debugLog("ehts key: %s  edts value: %s\n", "http-method", r.Method)
	// body
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return "", "", err
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		keysBuilder.WriteString(";")
		keysBuilder.WriteString("body")
		valuesBuilder.Write(body)
	}
	debugLog("\n")
	debugLog("ehts: %s\n", keysBuilder.String())
	debugLog("edts: %s\n", valuesBuilder.String())

	// Create the hash
	edtsHash := sha256.New()
	if _, err := edtsHash.Write([]byte(valuesBuilder.String())); err != nil {
		return "", "", err
	}
	edtsBase64 := base64.URLEncoding.EncodeToString(edtsHash.Sum(nil))
	// Remove the base64 padding, otherwise it won't work
	edtsBase64 = strings.ReplaceAll(edtsBase64, "=", "")
	debugLog("edtsBase64: %s\n\n", edtsBase64)
	return keysBuilder.String(), edtsBase64, nil
}

// Build - creates a T-Mobile JWT PoP token and returns it
func (pts PoPTokenBuilder) Build(r *http.Request) (string, error) {
	// Prepare the data
	ehts, edts, err := buildEHTSAndEDTS(r)
	if err != nil {
		return "", err
	}

	// Prepare the JWT PoP token
	now := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"v":    1,
		"ehts": ehts,
		"edts": edts,
		"iat":  now,
		"exp":  now + (2 * 60), // token is valid for 2 minutes
		"jti":  uuid.New().String(),
	})

	// Create and sign the PoP token
	pop, err := token.SignedString(pts.privateKey)
	if err != nil {
		return "", err
	}

	return pop, nil
}

// Sign - creates and signs a T-Mobile JWT PoP token and adds it to the request
func (pts PoPTokenBuilder) Sign(r *http.Request) error {
	// Build the PoP token
	pop, err := pts.Build(r)
	if err != nil {
		return err
	}

	// Add the PoP token to the request
	r.Header.Set("X-Authorization", pop)

	return nil
}
