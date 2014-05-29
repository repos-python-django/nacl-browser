/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var test = require("tape");
var nacl = require("../");
var util = require("./util.js");

var vectors = [
  // https://en.wikipedia.org/wiki/SHA-512#Examples_of_SHA-2_variants

  {
    name: "hash_sha256",
    msg: "The quick brown fox jumps over the lazy dog",
    hash: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
  },

  {
    name: "hash_sha256",
    msg: "The quick brown fox jumps over the lazy dog.",
    hash: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
  },

  {
    name: "hash_sha512",
    msg: "The quick brown fox jumps over the lazy dog",
    hash: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
  },

  {
    name: "hash_sha512",
    msg: "The quick brown fox jumps over the lazy dog.",
    hash: "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"
  }
];

test("[nacl.hash]", function (t) {
  var counter = 0;

  (function next_vector() {
    if (!vectors.length) {
      return;
    }

    var vector = vectors.shift();
    var name = vector.name;
    var msg = util.encode_utf8(vector.msg);

    // Test the current vector.
    t.test(name + " (#" + ++counter + ")", function (t) {
      t.plan(2);

      // Hash.
      nacl[name](msg).then(function (result) {
        t.equal(result.byteLength, nacl[name + "_BYTES"], "valid hash length");
        t.equal(util.to_hex(result), vector.hash, "valid hash result");

        next_vector();
      });
    });
  })();
});
