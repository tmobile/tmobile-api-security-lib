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
 * Defines the function for the PoP Token Builder without passphrase
 */
function buildPopToken(ehtsKeyValMap, privateKeyPemString) {
	buildPopTokenWithPassword(ehtsKeyValMap, privateKeyPemString, null);
}

/*
 * Defines the function for the PoP Token Builder with passphrase.
 */
function buildPopTokenWithPassword(ehtsKeyValMap, privateKeyPemString, passphrase) {
	/*
	 param ehtsKeyValMap - Map to be signed
	 param privateKeyPemString - Private Key PEM string
	 param passphrase - Private Key passphrase (optional)
	*/
	var strEhts = '';
	var strToHash = '';
	var strToken = '';
	for (var [key, value] of ehtsKeyValMap) {
		if (strEhts.length > 0) {
			strEhts = strEhts + ";";
		}
		strEhts = strEhts + key;
		strToHash = strToHash + value;
	}

	var strHash = KJUR.crypto.Util.sha256(strToHash);
	var strEdtsHashB64U = hextob64u(strHash);

	var currentTimeInSeconds = KJUR.jws.IntDate.get('now');
	var expTime = currentTimeInSeconds + (2 * 60); // token is valid for 2 minutes

	var objClaim = {
		v: 1,
		edts: strEdtsHashB64U,
		exp: expTime,
		ehts: strEhts,
		iat: currentTimeInSeconds,
		jti: createGUID()
	};

	var objHeader = { 'alg': 'RS256', 'typ': 'JWT' };
	if (passphrase) {
		var objKey = KEYUTIL.getKey(privateKeyPemString, passphrase)
		strToken = KJUR.jws.JWS.sign(null, objHeader, objClaim, objKey);
	} else {
		strToken = KJUR.jws.JWS.sign(null, objHeader, objClaim, privateKeyPemString);
	}
	
	return strToken;
}

/*
 * Defines the function to generate a unique ID
 */
function createGUID() {
	function randomStr() {
		return Math.floor((1 + Math.random()) * 0x10000)
			.toString(16)
			.substring(1);
	}
	return randomStr() + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + randomStr() + randomStr();
}
