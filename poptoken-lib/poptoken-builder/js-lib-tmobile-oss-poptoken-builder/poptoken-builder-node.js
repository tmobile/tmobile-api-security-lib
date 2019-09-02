/**
  Nodejs Template Project
  @module: js poptoken utils
  @description: Defines functions for the pop token JavaScript Utility
  @author: abhardw16
  @version: 1.0
**/
var rs = require('jsrsasign');

module.exports = {
	buildPopToken: function (ehtsKeyValuMap, privateKeyPemString) {
		/*
		 param ehtsKeyValuMap - Map to be signed
		 param privateKeyPemString - Private Key PEM string
		*/
		var objClaim = {};
		var strEhts = '';
		var strToHash = '';
		var strToken = '';
		var curTime = "now";
		var currentTimeInSeconds = Math.floor(new Date().getTime() / 1000);
		var expTime = currentTimeInSeconds + (2 * 60); // token is valid for 2 minutes

		for (var [key, value] of ehtsKeyValuMap) {
			if (strEhts.length > 0) {
				strEhts = strEhts + ";";
			}
			strEhts = strEhts + key;
			strToHash = strToHash + value;
		}

		var strHash = rs.KJUR.crypto.Util.sha256(strToHash);
		var strEdtsHashB64U = rs.hextob64u(strHash);

		var strUniq = module.exports.createGUID();

		if (strEdtsHashB64U.length > 0) {
			objClaim.edts = strEdtsHashB64U;
		}

		objClaim.v = '1';

		if (expTime != '') {
			objClaim.exp = expTime;
		}

		if (strEhts.length > 0) {
			objClaim.ehts = strEhts;
		}

		if (curTime != '') {
			objClaim.iat = rs.KJUR.jws.IntDate.get(curTime);
		}

		if (strUniq.length > 0) {
			objClaim.jti = strUniq;
		}

		var sClaim = JSON.stringify(objClaim);
		var alg = 'RS256';
		var pHeader = { 'alg': alg, 'typ': 'JWT' };
		var sHeader = JSON.stringify(pHeader);

		strToken = rs.KJUR.jws.JWS.sign(null, sHeader, sClaim, privateKeyPemString);

		return strToken;
	},

	buildPopTokenWithPassword: function (ehtsKeyValuMap, encryptedPrivateKeyPemString, password) {
		/*
		 param ehtsKeyValuMap - Map to be signed
		 param privateKeyPemString - Private Key PEM string
		 param password - Private Key password
		*/
		var objClaim = {};
		var strEhts = '';
		var strToHash = '';
		var strToken = '';
		var curTime = "now";
		var currentTimeInSeconds = Math.floor(new Date().getTime() / 1000);
		var expTime = currentTimeInSeconds + (2 * 60); // token is valid for 2 minutes


		for (var [key, value] of ehtsKeyValuMap) {
			if (strEhts.length > 0) {
				strEhts = strEhts + ";";
			}
			strEhts = strEhts + key;
			strToHash = strToHash + value;
		}

		var strHash = rs.KJUR.crypto.Util.sha256(strToHash);
		var strEdtsHashB64U = rs.hextob64u(strHash);

		var strUniq = module.exports.createGUID();

		if (strEdtsHashB64U.length > 0) {
			objClaim.edts = strEdtsHashB64U;
		}

		objClaim.v = '1';

		if (expTime != '') {
			objClaim.exp = expTime;
		}

		if (strEhts.length > 0) {
			objClaim.ehts = strEhts;
		}

		if (curTime != '') {
			objClaim.iat = rs.KJUR.jws.IntDate.get(curTime);
		}

		if (strUniq.length > 0) {
			objClaim.jti = strUniq;
		}

		var sClaim = JSON.stringify(objClaim);
		var alg = 'RS256';
		var pHeader = { 'alg': alg, 'typ': 'JWT' };
		var sHeader = JSON.stringify(pHeader);

		var keyObj = rs.KEYUTIL.getKey(encryptedPrivateKeyPemString, password)

		var privateKeyPemString = encryptedPrivateKeyPemString;

		strToken = rs.KJUR.jws.JWS.sign(null, sHeader, sClaim, keyObj);

		return strToken;
	},

	createGUID: function () {
		function randomStr() {
			return Math.floor((1 + Math.random()) * 0x10000)
				.toString(16)
				.substring(1);
		}
		return randomStr() + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + randomStr() + randomStr();
	}
};
