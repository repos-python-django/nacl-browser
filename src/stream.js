/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

function importKey(key) {
  return crypto.subtle.importKey("raw", key, "AES-CTR", false, ["encrypt"]);
}

function aes_ctr(key, nonce, msg, key_bytes) {
  if (key.byteLength != key_bytes) {
    throw new Error("Invalid key size");
  }

  if (nonce.byteLength != 16) {
    throw new Error("Invalid nonce size");
  }

  var algo = {name: "AES-CTR", counter: nonce, length: 32};

  return importKey(key).then(function (key) {
    return crypto.subtle.encrypt(algo, key, msg);
  });
}

function aes128_ctr(key, nonce, msg) {
  return aes_ctr(key, nonce, msg, 16);
}

function aes128_ctr_raw(key, nonce, len) {
  return aes128_ctr(key, nonce, new Uint8Array(len));
}

function aes256_ctr(key, nonce, msg) {
  return aes_ctr(key, nonce, msg, 32);
}

function aes256_ctr_raw(key, nonce, len) {
  return aes256_ctr(key, nonce, new Uint8Array(len));
}

module.exports = {
  stream_xor: aes256_ctr,
  stream: aes256_ctr_raw,

  stream_aes128ctr_xor: aes128_ctr,
  stream_aes128ctr: aes128_ctr_raw,

  stream_aes256ctr_xor: aes256_ctr,
  stream_aes256ctr: aes256_ctr_raw
};
