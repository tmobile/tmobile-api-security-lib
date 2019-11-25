# Golang - PoP Token Builder Library

Golang library to build PoP tokens to the T-Mobile specification.

See `poptokenbuilder_test.go` for example usage

### Basic overview:

This library works by taking in a standard Go libray http.Request struct, using it's in formation to generate the PoP token, then writing the token back to the Request (optionally this part can be done manually by using `Build()` instead of `Sign()`).

Both unencrypted and encrypted (pass-phrase protected) RSA keys are supported, either hard-coded or loaded from the filesystem.

Generated tokens have been tested and validated against the production API calls.
