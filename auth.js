/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

function importKey(key, usage) {
  if (key.byteLength != 32) {
    throw new Error("Invalid key size");
  }

  var algo = {name: "HMAC", hash: "SHA-256"};
  return crypto.subtle.importKey("raw", key, algo, false, [usage]);
}

function hmac_sha256(key, msg) {
  return importKey(key, "sign").then(function (key) {
    return crypto.subtle.sign("HMAC", key, msg);
  });
}

function hmac_sha256_verify(key, msg, mac) {
  if (mac.byteLength != 32) {
    throw new Error("Invalid MAC size");
  }

  return importKey(key, "verify").then(function (key) {
    return crypto.subtle.verify("HMAC", key, mac, msg);
  });
}

module.exports = {
  auth: hmac_sha256,
  auth_verify: hmac_sha256_verify,
  auth_hmacsha256: hmac_sha256,
  auth_hmacsha256_verify: hmac_sha256_verify
};
