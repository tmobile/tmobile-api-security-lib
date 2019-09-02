# T-Mobile PoP Token Builder JavaScript Library
  
##  Using the PoP Token Builder JavaScript Library

**Using it in HTML/Client UI page:**

Link to the below JavaScript libraries in an HTML/client UI page.

1. [poptoken-builder.js](./poptoken-builder.js) (available in js_lib directory)
2. [jsrsasign-all-min.js](./js-lib/jsrsasign-all-min.js) (available in root directory)

Refer to [poptoken-builder-test.html](./html_example/poptoken-builder-test.html) to find out how to use the PoP token builder library in an HTML page.

**Using it in Node.js Application :**

Install the node modules using the following command.

```
npm install
```

The above command will create `node_modules` directory and will install the necessary node modules in it.

Refer to [index-poptoken-builder.js](./node_example/index-poptoken-builder.js) to find out how to use the PoP token builder library in a Node.js application.

## Implementation Details

The T-Mobile PoP Token Builder library follows the following logic for creating the PoP token.

* Sets up the edts (external data to sign) / ehts (external headers to sign) claims in PoP token using the specified ehts key-value map. The library uses SHA256 algorithm for calculating the edts and then the final edts value is encoded using Base64 URL encoding.
* Signs the PoP token using the specified RSA private key.
* Creates the PoP token with 2 minutes of validity period.

## Determining the ehts Key Name:

* All required header and body fields and its values need to be defined. 
* For HTTP request URI, "uri" should be used as ehts key name. Example: If the URL is `https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000` then only `/commerce/v1/orders?account-number=0000000000` should be used as ehts value. The query parameter values part of "uri" ehts value should be in URL encoded format. 
* For HTTP method, "http-method" should be used as ehts key name.  
* For HTTP request headers, the header name should be used as ehts key name.  
* For HTTP request body, "body" should be used as ehts key name.  

## Supported Key Format

PoP token builder and validator libraries are currently supporting PKCS8 key format.

**Using Non Encrypted Keys:**

Below commands shows how to create private and public keys in PKCS8 format:

```
# Creates private key in PKCS1 format
openssl genrsa -out private-key-pkcs1.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private-key-pkcs1.pem -outform PEM -nocrypt -out private-key-pkcs8.pem

# Creates public key in PKCS8 format
openssl rsa -in private-key-pkcs8.pem -outform PEM -pubout -out public-key.pem

```
  
##  Building the PoP Token Using Private Key PEM String

The following code snippet demonstrates how to use the PoP token builder Java Script library to build the PoP token. For the complete HTML/JS code, please refer to [poptoken-builder-test.html](poptoken-builder-test.html).
 
```
// Link the required JavaScript files
<script language="JavaScript" type="text/javascript" src="./jsrsasign-all-min.js"></script>
<script language="JavaScript" type="text/javascript" src="./poptoken-builder.js"></script>

// The below command can be used to generate PKCS8 private key pem string
// openssl genrsa -out private-key-pkcs1.pem 2048
// openssl pkcs8 -topk8 -inform PEM -in private-key-pkcs1.pem -outform PEM -nocrypt -out private-key-pkcs8.pem
// openssl rsa -in private-key-pkcs8.pem -outform PEM -pubout -out public-key.pem

var privateKeyPemString = "" +
"-----BEGIN PRIVATE KEY-----\n" +
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2ccmjG1gBJwTN\n" +
"slQJAEYmQYZl0j2LI+URPXCOjWj3hcmjYQPdfd+ZeCKuA8aUgXFox1xBdIxqAnY4\n" +
"8pW0MyMlwtyOiMpcnelzuKl9CqktbLSxdOUDo/wOd2d4lKnuvIHSKeoETfENroVM\n" +
"3Cm3CFJ8tmpQRjMYh4MBxZh2V3XClhES8t12DI+Lznr5BWvk8oIjRRs99Xu2n9Dy\n" +
"RoYal3trb+0ncdmr5EDhDE/sBC6MAk37UjyS8sty37+tbcgLkn42WISemSLnA4IO\n" +
"yiW6EZHcSTXj/vUCHLJjwDyihMCUWfA6NxLPlPFcLaD4o8DEg2VOa89rL9t1SoBo\n" +
"wsEhLn/5AgMBAAECggEBAI0tReOSMCpMIDpvyPliHeZShAZchsUZlJMfoO6eXGBV\n" +
"Ra/ITa5iTdk7DlLrlwmplLGIu0nnPxR1LThp9xAHFiaNQBCHp1e91j124qhgzILb\n" +
"AIPlOaX0igJDwWycVVboxeh0CKMmEOcOahYMs7bvmKzqlx/hAn7ztZt0ZMMGcJiO\n" +
"KLIUBVOjFoCeDoLgjvNrBduvHCnQ2CcJLnBxml7oRYc63ipBeJmC+aGjCIdKGtFK\n" +
"WRGiYrM4n5h4CKEnMTaZ+KAkJTmS43CBobDbp+rJbfpsGo7+xCt1VyjZfpMjF3zB\n" +
"oK8LywuFDddwopcMMkCHbFo7sM9HBqW7vyzgxlBZ5QECgYEA8f6XN2o9QV57H6GO\n" +
"5X0tCe5zdHt4NIHGYJfC3gVkduurMg8q/DBHBodFokp53OC48zOh6NzJOyhWacLq\n" +
"H6oSLQy2oSIBIXKC3Wt9yreOa3g69tQTN+CT7OT87KMvV0nYf7lXWTxjgMLEgClh\n" +
"0tDDls3+03oIQ4FpP7LBc6WhhRkCgYEAwQDmOtAYP51xuuVXl3Z0x9r6xfeIq/NG\n" +
"IqlVcq6tB+yWJ+YtVoysboyTcfJbGCPRMeQlrntfHSkdjMWb8R+xwt5c0eAmcL8m\n" +
"9tEtjHFa2QkqbKkQ3wRmS6KXJ8WJGY2opnVPwpWHpJn2qg01NkgQFfkjgUkWPSZx\n" +
"oauKcjiwTeECfx1NtwH+22wPBNnPtn4TqmCJf3GbgfLZxCvuNKqt/HxqDVEChTIE\n" +
"ppUjzErauecFT2Aj4HdSRQvk1pH4CGHNNmY+I99fPsPOGgq1+YWStKxO4tUA2VLq\n" +
"3v7Qu8/r8s+fIZhV2T31EheFfkYGvNHKdeTNDQ6OuHF0Okp8WvCmHekCgYEAtfW+\n" +
"GXa1Vcx/O+AbG54/bWjDgr7j6JE771PMTonmchEYY9d7qRyJONRp8kS2o2SpRqs8\n" +
"52pC+wAXbu+jHMpv0jPIOMpmE2f0OUBu+/im2PXuPHGMiWXhd697aLCwmBnZBc6V\n" +
"+vL05jeNuTcoktuP5tdzJOGeCNrkyLIsnZFajqECgYAGEbakt+8OpDxFVIFzPWGT\n" +
"f2KIeBYHX74JiJ3C0iGYvTiIO2cPuM3sSzUfx6+kmCqKioLueMW6BcAIy0WdELOh\n" +
"P1MaK10FQ12qFFrsnOZjVPoxZ4xVtzN3e4uCyc69xT2bAUpzoVKCMaCSRNv/unGk\n" +
"zHNmq7/VPITL5UgtZ5nk6g==\n" +
"-----END PRIVATE KEY-----\n";

// STEP 1: Build the Javascript Map of ehts (external headers to sign) key and values
mapehtsKeyValue.set('Content-Type', 'application/json');
mapehtsKeyValue.set('Authorization', 'Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS');
mapehtsKeyValue.set('uri', '/commerce/v1/orders');
mapehtsKeyValue.set('http-method', 'POST');
mapehtsKeyValue.set('body', '{"orderId": 100, "product": "Mobile Phone"}');

The validity of 2 minutes has been defined in the method. It can be changed as required.

// STEP 2: Generate PoP token using PoPTokenBuilder
var popToken = '';
var ehtsKeyValuMap = new Map();
setEhtsKeyValueMap(ehtsKeyValuMap);
popToken = buildPopToken(ehtsKeyValuMap, privateKeyPemString);

```
