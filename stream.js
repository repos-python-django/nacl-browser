/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

function importKey(key) {
  return crypto.subtle.importKey("raw", key, "AES-CTR", false, ["encrypt"]);
}

function aes_ctr(key, iv, msg, key_bytes) {
  if (key.byteLength != key_bytes) {
    throw new Error("Invalid key size");
  }

  if (iv.byteLength != 16) {
    throw new Error("Invalid IV size");
  }

  var algo = {name: "AES-CTR", counter: iv, length: 32};

  return importKey(key).then(function (key) {
    return crypto.subtle.encrypt(algo, key, msg);
  });
}

function aes128_ctr(key, iv, msg) {
  return aes_ctr(key, iv, msg, 16);
}

function aes128_ctr_raw(key, iv, len) {
  return aes128_ctr(key, iv, new Uint8Array(len));
}

function aes256_ctr(key, iv, msg) {
  return aes_ctr(key, iv, msg, 32);
}

function aes256_ctr_raw(key, iv, len) {
  return aes256_ctr(key, iv, new Uint8Array(len));
}

module.exports = {
  stream_xor: aes256_ctr,
  stream: aes256_ctr_raw,

  stream_aes128ctr_xor: aes128_ctr,
  stream_aes128ctr: aes128_ctr_raw,

  stream_aes256ctr_xor: aes256_ctr,
  stream_aes256ctr: aes256_ctr_raw
};
