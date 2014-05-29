/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var test = require("tape");
var nacl = require("../");
var util = require("./util.js");

test("auth0", function (t) {
  t.plan(3);

  var data = util.encode_utf8("Hi There");
  var key = util.from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});

test("auth", function (t) {
  t.plan(3);

  var data = util.encode_utf8("what do ya want for nothing?");
  var key = util.encode_utf8("Jefe");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});

test("auth5", function (t) {
  t.plan(3);

  var data = util.from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
  var key = util.from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});

test("auth4", function (t) {
  t.plan(3);

  var data = util.from_hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
  var key = util.from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});

test("auth2", function (t) {
  t.plan(3);

  var data = util.encode_utf8("Test Using Larger Than Block-Size Key - Hash Key First");
  var key = util.from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});

test("auth3", function (t) {
  t.plan(3);

  var data = util.encode_utf8("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
  var key = util.from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

  nacl.auth(key, data).then(function (result) {
    t.equal(result.byteLength, nacl.auth_BYTES);
    t.equal(util.to_hex(result), "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");

    nacl.auth_verify(key, data, result).then(function (result) {
      t.ok(result);
    });
  });
});
