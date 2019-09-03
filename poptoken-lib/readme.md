# PoP Token Libraries

The OAuth 2.0 bearer token specification, as defined in RFC6750, allows any party in possession of a bearer token (a "bearer") to get access to the associated resources (without demonstrating possession of a cryptographic key). To prevent misuse, bearer tokens must be protected from disclosure in transit and at rest.

Some scenarios demand additional security protection, whereby a client needs to demonstrate possession of cryptographic keying material when accessing a protected resource.

Proof of possession (PoP) provides a mechanism to bind key material to access tokens. This key material can then be used by the client to add signatures to outgoing HTTP requests to the resource server. The resource server in turn can use the key material to make sure that the sender is the same entity that requested the token in the first place (as opposed to someone who stole the token in transit or at rest).

Proof of possession (PoP) helps enabling the message integrity and also helps avoiding the transaction replay and token theft. For each API request the new PoP token is created by API consumer and signed by client's private key which can then be verified using client's public key at API gateway.


## PoP Token Flow

![PoP Token Sequence Diagram](./images/pop_token_sequence_diagram.png)


## PoP Token Format

The format of the PoP token used by T-Mobile is:
```
Header: {alg, type} 
Body { 
  iat: <epoch time> 
  exp: <epoch time> 
  ehts: <authorization; content_type; uri; http-method; body> => All request headers, URI, HTTP method and body fields used to create hash
  edts: <Base64UrlSafeEncoding[SHA256(all ehts claim values as a concatenated string)]">
  jti: <unique identifier> 
  v: "1"
}
Signature: <digitalSignature>
```


## PoP Token Builder Library

The PoP token builder library can be used to create a PoP token.

For more information on PoP token builder library, please refer to the - [PoP Token Builder Library](./poptoken-builder).


## PoP Token Validator Library

The PoP token validator library can be used to validate a PoP token.

For more information on PoP token validator library, please refer to the - [PoP Token Validator Library](./poptoken-validator).
