/*
 * Copyright 2019 T-Mobile US, Inc.
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
 
/*
 * Node sample for PoP token builder.
 */

var popTokenBuilderUtil = require('../poptoken-builder-node');

var popToken = '';
var ehtsKeyValueMap = new Map();

ehtsKeyValueMap.set('Content-Type', 'application/json');
ehtsKeyValueMap.set('Authorization', 'Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS');
ehtsKeyValueMap.set('uri', '/commerce/v1/orders');
ehtsKeyValueMap.set('http-method', 'POST');
ehtsKeyValueMap.set('body', '{"orderId": 100, "product": "Mobile Phone"}');

var privateKeyPemStr = "" +
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

popToken = popTokenBuilderUtil.buildPopToken(ehtsKeyValueMap, privateKeyPemStr);
console.log("The JWT for the given RSA PEM is - " + popToken);
