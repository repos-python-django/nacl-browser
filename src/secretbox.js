/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

function importKey(key, usage) {
  if (key.byteLength != 32) {
    throw new Error("Invalid key size");
  }

  return crypto.subtle.importKey("raw", key, "AES-GCM", false, [usage]);
}

function aes256_gcm(key, iv, msg, action) {
  if (iv.byteLength != 16) {
    throw new Error("Invalid IV size");
  }

  return importKey(key, action).then(function (key) {
    var algo = {name: "AES-GCM", iv: iv, tagLength: 128};
    return crypto.subtle[action](algo, key, msg);
  });
}

function aes256_gcm_encrypt(key, iv, msg) {
  return aes256_gcm(key, iv, msg, "encrypt");
}

function aes256_gcm_decrypt(key, iv, msg) {
  if (msg.byteLength < 16) {
    throw new Error("Message too short to include tag");
  }

  return aes256_gcm(key, iv, msg, "decrypt");
}

module.exports = {
  secretbox: aes256_gcm_encrypt,
  secretbox_open: aes256_gcm_decrypt,

  secretbox_aes256gcm: aes256_gcm_encrypt,
  secretbox_aes256gcm_open: aes256_gcm_decrypt
};
