/*
 * js poptoken utils
 */
/*!
functions for the pop token JS Utility
*/

function buildPopToken(ehtsKeyValuMap, privateKeyPemString) {
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

  var strHash = KJUR.crypto.Util.sha256(strToHash);
  var strEdtsHashB64U = hextob64u(strHash);

  strUniq = createGUID();

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
    objClaim.iat = KJUR.jws.IntDate.get(curTime);
  }

  if (strUniq.length > 0) {
    objClaim.jti = strUniq;
  }

  var sClaim = JSON.stringify(objClaim);
  var alg = 'RS256';
  var pHeader = { 'alg': alg, 'typ': 'JWT' };
  var sHeader = JSON.stringify(pHeader);

  strToken = KJUR.jws.JWS.sign(null, sHeader, sClaim, privateKeyPemString);

  return strToken;
}

function buildPopTokenWithPassword(ehtsKeyValuMap, privateKeyEncryptedString, passwd) {
  /*
   param ehtsKeyValuMap - Map to be signed
   param privateKeyPemString - Private Key PEM string
   param passwd - Private Key password
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

  var strHash = KJUR.crypto.Util.sha256(strToHash);
  var strEdtsHashB64U = hextob64u(strHash);

  strUniq = createGUID();

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
    objClaim.iat = KJUR.jws.IntDate.get(curTime);
  }

  if (strUniq.length > 0) {
    objClaim.jti = strUniq;
  }

  var sClaim = JSON.stringify(objClaim);
  var alg = 'RS256';
  var pHeader = { 'alg': alg, 'typ': 'JWT' };
  var sHeader = JSON.stringify(pHeader);
  var keyObj = KEYUTIL.getKey(privateKeyEncryptedString, passwd)

  strToken = KJUR.jws.JWS.sign(null, sHeader, sClaim, keyObj);

  return strToken;
}

function createGUID() {
  function randomStr() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }
  return randomStr() + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + '-' + randomStr() + randomStr() + randomStr();
}
