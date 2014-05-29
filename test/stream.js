/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var test = require("tape");
var nacl = require("../");
var util = require("./util.js");

var vectors = [
  // http://tools.ietf.org/html/rfc3686#section-6

  {
    name: "stream_aes128ctr",
    key: "ae6852f8121067cc4bf7a5765577f39e",
    iv: "00000030000000000000000000000001",
    msg: "53696e676c6520626c6f636b206d7367",
    ct: "e4095d4fb7a7b3792d6175a3261311b8",
    raw: "b7603328dbc2931b410e16c8067e62df"
  },

  {
    name: "stream_aes128ctr",
    key: "7e24067817fae0d743d6ce1f32539163",
    iv: "006cb6dbc0543b59da48d90b00000001",
    msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ct: "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",
    raw: "5105a305128f74de71044be582d7dd87fb3f0cef52cf41dfe4ff2ac48d5ca037"
  },

  {
    name: "stream_aes128ctr",
    key: "7691be035e5020a8ac6e618529f9a0dc",
    iv: "00e0017b27777f3f4a1786f000000001",
    msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
    ct: "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",
    raw: "c1ce4aab9b2afbdec74f58e2e3d67cd85551b638ca786e21cd8346f1b2ee0e4c0593250c"
  },

  {
    name: "stream_aes256ctr",
    key: "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
    iv: "00000060db5672c97aa8f0b200000001",
    msg: "53696e676c6520626c6f636b206d7367",
    ct: "145ad01dbf824ec7560863dc71e3e0c0",
    raw: "4733be7ad3e76ea53a6700b7518e93a7"
  },

  {
    name: "stream_aes256ctr",
    key: "f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884",
    iv: "00faac24c1585ef15a43d87500000001",
    msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ct: "f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c",
    raw: "f05f21183c91672b41e70a008c43bca6a82179439b968b7d4d2999068f59b103"
  },

  {
    name: "stream_aes256ctr",
    key: "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
    iv: "001cc5b751a51d70a1c1114800000001",
    msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
    ct: "eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8",
    raw: "eb6d5081190ebdf0c67c9e4d26c741a5a416cd95717ceb10ec95daae9fcb19003ee1c49b"
  },

  // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

  {
    name: "stream_aes128ctr",
    key: "2b7e151628aed2a6abf7158809cf4f3c",
    iv: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    ct: "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
  },

  {
    name: "stream_aes256ctr",
    key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    iv: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    msg: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    ct: "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
  }
];

function try_arg_sizes(method, key_len, iv_len) {
  var msg = util.encode_utf8("Just a test message.");
  var key = crypto.getRandomValues(new Uint8Array(key_len));
  var iv = crypto.getRandomValues(new Uint8Array(iv_len));
  nacl[method](key, iv, msg);
}

test("[nacl.stream]", function (t) {
  var counter = 0;

  (function next_vector() {
    if (!vectors.length) {
      return;
    }

    var vector = vectors.shift();
    var name = vector.name;
    var key = util.from_hex(vector.key);
    var iv = util.from_hex(vector.iv);
    var msg = util.from_hex(vector.msg);

    // Test the current vector.
    t.test(name + "_xor (#" + ++counter + ")", function (t) {
      t.plan(2);

      // Encrypt.
      nacl[name + "_xor"](key, iv, msg).then(function (result) {
        t.equal(util.to_hex(result), vector.ct, "valid encryption");

        // Decrypt.
        nacl[name + "_xor"](key, iv, result).then(function (result) {
          t.equal(util.to_hex(result), util.to_hex(msg), "valid decryption");

          // Next test vector.
          next_vector();
        });
      });
    });

    if (!("raw" in vector)) {
      return;
    }

    // Test the current vector's raw key stream.
    t.test(name + "_raw (#" + ++counter + ")", function (t) {
      t.plan(1);

      nacl[name](key, iv, msg.byteLength).then(function (result) {
        t.equal(util.to_hex(result), vector.raw, "valid key stream");
      });
    });
  })();
});

test("[nacl.stream] 128-bit failures", function (t) {
  // Check that the right sizes work.
  try_arg_sizes("stream_aes128ctr", 16, 16);

  t.throws(function () {
    try_arg_sizes("stream_aes128ctr", 15, 16);
  }, "Key size too small.");

  t.throws(function () {
    try_arg_sizes("stream_aes128ctr", 17, 16);
  }, "Key size too big.");

  t.throws(function () {
    try_arg_sizes("stream_aes128ctr", 16, 15);
  }, "IV size too small.");

  t.throws(function () {
    try_arg_sizes("stream_aes128ctr", 16, 17);
  }, "IV size too big.");

  t.end();
});

test("[nacl.stream] 256-bit failures", function (t) {
  // Check that the right sizes work.
  try_arg_sizes("stream_aes256ctr", 32, 16);

  t.throws(function () {
    try_arg_sizes("stream_aes256ctr", 31, 16);
  }, "Key size too small.");

  t.throws(function () {
    try_arg_sizes("stream_aes256ctr", 33, 16);
  }, "Key size too big.");

  t.throws(function () {
    try_arg_sizes("stream_aes256ctr", 32, 15);
  }, "IV size too small.");

  t.throws(function () {
    try_arg_sizes("stream_aes256ctr", 32, 17);
  }, "IV size too big.");

  t.end();
});
