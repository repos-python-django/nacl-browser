/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var hash = require("./hash.js");
var auth_BYTES = hash.hash_sha512_BYTES;
var auth_KEYBYTES = hash.hash_sha512_BYTES;

function importKey(key, usage) {
  // TODO check key bytes

  var algo = {name: "HMAC", hash: "SHA-512"};
  return crypto.subtle.importKey("raw", key, algo, false, [usage]);
}

function hmac(key, msg) {
  /*var kbytes = auth_KEYBYTES;

  if (key.byteLength != kbytes) {
    throw new Error("hmac() key needs to be exactly " + kbytes + " bytes!");
  }*/

  return importKey(key, "sign").then(function (key) {
    return crypto.subtle.sign("HMAC", key, msg);
  });
}

function hmac_verify(key, msg, mac) {
  return importKey(key, "verify").then(function (key) {
    return crypto.subtle.verify("HMAC", key, mac, msg);
  });
}

// TODO crypto_auth_hmacsha256
// TODO crypto_auth_hmacsha512256

module.exports = {
  auth: hmac,
  auth_verify: hmac_verify,

  auth_BYTES: auth_BYTES,
  auth_KEYBYTES: auth_KEYBYTES
};
