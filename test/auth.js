/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var test = require("tape");
var nacl = require("../");
var util = require("./util.js");

var vectors = [
  // https://tools.ietf.org/html/rfc4231#section-4

  {
    name: "auth_hmacsha256",
    key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000",
    msg: "4869205468657265",
    mac: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  },

  {
    name: "auth_hmacsha256",
    key: "4a65666500000000000000000000000000000000000000000000000000000000",
    msg: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    mac: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  },

  {
    name: "auth_hmacsha256",
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000",
    msg: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    mac: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
  },

  {
    name: "auth_hmacsha256",
    key: "0102030405060708090a0b0c0d0e0f1011121314151617181900000000000000",
    msg: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    mac: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
  },

  {
    name: "auth_hmacsha256",
    key: "45ad4b37c6e2fc0a2cfcc1b5da524132ec707615c2cae1dbbc43c97aa521db81",
    msg: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
    mac: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
  },

  {
    name: "auth_hmacsha256",
    key: "45ad4b37c6e2fc0a2cfcc1b5da524132ec707615c2cae1dbbc43c97aa521db81",
    msg: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
    mac: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
  }
];

function try_auth_key_size(key_len) {
  var msg = new TextEncoder("utf-8").encode("Just a test message.");
  var key = crypto.getRandomValues(new Uint8Array(key_len));
  var msg = crypto.getRandomValues(new Uint8Array(8));
  nacl.auth_hmacsha256(key, msg);
}

function try_verify_sizes(key_len, mac_len) {
  var msg = new TextEncoder("utf-8").encode("Just a test message.");
  var key = crypto.getRandomValues(new Uint8Array(key_len));
  var msg = crypto.getRandomValues(new Uint8Array(8));
  var mac = crypto.getRandomValues(new Uint8Array(mac_len));
  nacl.auth_hmacsha256_verify(key, msg, mac);
}

test("[nacl.auth]", function (t) {
  var counter = 0;

  (function next_vector() {
    if (!vectors.length) {
      return;
    }

    var vector = vectors.shift();
    var name = vector.name;
    var key = util.hex2abv(vector.key);
    var msg = util.hex2abv(vector.msg);

    // Test the current vector.
    t.test(name + " (#" + ++counter + ")", function (t) {
      t.plan(2);

      // Create MAC.
      nacl[name](key, msg).then(function (result) {
        t.equal(util.abv2hex(result), vector.mac, "valid mac");

        // Verify MAC.
        nacl[name + "_verify"](key, msg, result).then(function () {
          t.pass("mac verifies");
          next_vector();
        }, function () {
          t.fail("mac should have verified");
          next_vector();
        });
      });
    });
  })();
});

test("[nacl.auth] bad", function (t) {
  t.plan(1);

  var key = util.hex2abv("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000000000000000000000000");
  var msg = util.hex2abv("4869205468657265");

  // The first octet of the MAC has been set to zero.
  var mac = util.hex2abv("00344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  // Try to verify MAC.
  nacl.auth_hmacsha256_verify(key, msg, mac).then(function () {
    t.fail("verification should have failed");
  }, function () {
    t.pass("verification failed");
  });
});

test("[nacl.auth] auth() failures", function (t) {
  // Check that the right key size works.
  try_auth_key_size(32);

  t.throws(function () {
    try_auth_key_size(31);
  }, "Key size too small.");

  t.throws(function () {
    try_auth_key_size(33);
  }, "Key size too big.");

  t.end();
});

test("[nacl.auth] auth_verify() failures", function (t) {
  // Check that the right sizes work.
  try_verify_sizes(32, 32);

  t.throws(function () {
    try_verify_sizes(31, 32);
  }, "Key size too small.");

  t.throws(function () {
    try_verify_sizes(33, 32);
  }, "Key size too big.");

  t.throws(function () {
    try_verify_sizes(32, 31);
  }, "MAC size too small.");

  t.throws(function () {
    try_verify_sizes(32, 33);
  }, "MAC size too big.");

  t.end();
});
