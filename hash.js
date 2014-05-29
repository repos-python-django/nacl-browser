/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var sha256_BYTES = 32;
var sha512_BYTES = 64;

function digest(algo, msg) {
  return crypto.subtle.digest(algo, msg);
}

function sha256(msg) {
  return digest("SHA-256", msg);
}

function sha512(msg) {
  return digest("SHA-512", msg);
}

module.exports = {
  hash: sha512,
  hash_BYTES: sha512_BYTES,

  hash_sha256: sha256,
  hash_sha256_BYTES: sha256_BYTES,

  hash_sha512: sha512,
  hash_sha512_BYTES: sha512_BYTES,
};
