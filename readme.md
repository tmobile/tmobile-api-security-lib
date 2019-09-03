# T-Mobile API Security Libraries

## Overview

"T-Mobile API Security Libraries" provides the libraries which can be leveraged to implement the API security within your enterprise. Currently it provides the PoP (Proof of Possession) token builder and validator related libraries. Proof of possession (PoP) helps enabling the message integrity and also helps avoiding the transaction replay and token theft. For each API request the new PoP token is created by API consumer and signed by the client's private key which can then be verified using the client's public key at API gateway. The PoP token builder libraries are available in multiple languages.

## Directory Structure

<font name="Consolas">
<pre>
└── <a href=".">tmobile-api-security-lib</a>                                # T-Mobile API Security Lib Parent Directory
    └── <a href="./poptoken-lib">poptoken-lib</a>                                        # PoP Token Lib Parent Directory
        ├── <a href="./poptoken-lib/poptoken-builder">poptoken-builder</a>                                # PoP Token Builder Lib Parent Directory
        │   ├── <a href="./poptoken-lib/poptoken-builder/java-lib-tmobile-oss-poptoken-builder">java-lib-tmobile-oss-poptoken-builder</a>       # Java PoP Token Builder Lib
        │   ├── <a href="./poptoken-lib/poptoken-builder/js-lib-tmobile-oss-poptoken-builder">js-lib-tmobile-oss-poptoken-builder</a>         # JavaScript PoP Token Builder Lib
        │   ├── <a href="./poptoken-lib/poptoken-builder/android-lib-tmobile-oss-poptoken-builder">android-lib-tmobile-oss-poptoken-builder</a>    # Android PoP Token Builder Lib
        │   └── <a href="./poptoken-lib/poptoken-builder/ios-lib-tmobile-oss-poptoken-builder">ios-lib-tmobile-oss-poptoken-builder</a>        # iOS PoP Token Builder Lib
        └── <a href="./poptoken-lib/poptoken-validator">poptoken-validator</a>                              # PoP Token Validator Lib Parent Directory
            └── <a href="./poptoken-lib/poptoken-validator/java-lib-tmobile-oss-poptoken-validator">java-lib-tmobile-oss-poptoken-validator</a>     # Java PoP Token Validator Lib
</pre>
</font>

## Available Libraries 

### PoP Token Libraries

The OAuth 2.0 bearer token specification, as defined in RFC6750, allows any party in possession of a bearer token (a "bearer") to get access to the associated resources (without demonstrating possession of a cryptographic key). To prevent misuse, bearer tokens must be protected from disclosure in transit and at rest.

Some scenarios demand additional security protection, whereby a client needs to demonstrate possession of cryptographic keying material when accessing a protected resource.

Proof of possession (PoP) provides a mechanism to bind key material to access tokens. This key material can then be used by the client to add signatures to outgoing HTTP requests to the resource server. The resource server in turn can use the key material to make sure that the sender is the same entity that requested the token in the first place (as opposed to someone who stole the token in transit or at rest).

Proof of possession (PoP) helps enabling the message integrity and also helps avoiding the transaction replay and token theft. For each API request the new PoP token is created by API consumer and signed by client's private key which can then be verified using client's public key at API gateway.

For more information on PoP token libraries, please refer to the readme file - [PoP Token Library Readme.md](./poptoken-lib).

## License

The T-Mobile API security libraries are released under the [Apache 2.0 License](./LICENSE).
