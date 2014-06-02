/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var test = require("tape");
var sjcl = require("sjcl");
var nacl = require("../");
var util = require("./util.js");

function random_bytes(num) {
  return crypto.getRandomValues(new Uint8Array(num));
}

function sjcl_encrypt(key, iv, msg) {
  var hex = sjcl.codec.hex;

  key = hex.toBits(util.abv2hex(key));
  var aes = new sjcl.cipher.aes(key);

  iv = hex.toBits(util.abv2hex(iv));
  msg = hex.toBits(util.abv2hex(msg));

  var ct = sjcl.mode.gcm.encrypt(aes, msg, iv, [], 128 /* tag length */);
  return hex.fromBits(ct);
}

function try_arg_sizes(method, key_len, iv_len, msg_len) {
  var msg = crypto.getRandomValues(new Uint8Array(msg_len || 32));
  var key = crypto.getRandomValues(new Uint8Array(key_len));
  var iv = crypto.getRandomValues(new Uint8Array(iv_len));
  nacl[method](key, iv, msg);
}

test("[nacl.secretbox]", function (t) {
  // Couldn't find any test vectors for AES-256 with a 128-bit IV,
  // a 128-bit tag, and no associated data. Use random values and
  // the SJCL implementation as reference.
  for (var i = 0; i < 10; i++) {
    var bytes = Math.pow(2, i + 1);

    t.test("secretbox_aes256gcm (" + bytes + " byte message)", function (t) {
      t.plan(3);

      var key = random_bytes(32);
      var iv = random_bytes(16);
      var msg = random_bytes(bytes);

      // Encrypt.
      nacl.secretbox_aes256gcm(key, iv, msg).then(function (result) {
        t.equal(sjcl_encrypt(key, iv, msg), util.abv2hex(result), "valid encryption");

        // Decrypt.
        nacl.secretbox_aes256gcm_open(key, iv, result).then(function (result) {
          t.equal(util.abv2hex(msg), util.abv2hex(result), "valid decryption");
        });

        // Generate a new random key.
        key = random_bytes(32);

        // Try to decrypt.
        nacl.secretbox_aes256gcm_open(key, iv, result).then(function (result) {
          t.fail("decryption should have failed");
        }, function () {
          t.pass("decryption failed");
        });
      });
    });
  }
});

test("[nacl.secretbox] secretbox() failures", function (t) {
  // Check that the right sizes work.
  try_arg_sizes("secretbox_aes256gcm", 32, 16);

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm", 31, 16);
  }, "Key size too small.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm", 33, 16);
  }, "Key size too big.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm", 32, 15);
  }, "IV size too small.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm", 32, 17);
  }, "IV size too big.");

  t.end();
});

test("[nacl.secretbox] secretbox_open() failures", function (t) {
  // Check that the right sizes work.
  try_arg_sizes("secretbox_aes256gcm_open", 32, 16, 16);
  try_arg_sizes("secretbox_aes256gcm_open", 32, 16, 65536);

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm_open", 31, 16);
  }, "Key size too small.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm_open", 33, 16);
  }, "Key size too big.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm_open", 32, 15);
  }, "IV size too small.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm_open", 32, 17);
  }, "IV size too big.");

  t.throws(function () {
    try_arg_sizes("secretbox_aes256gcm_open", 32, 16, 15);
  }, "Message size too small.");

  t.end();
});
