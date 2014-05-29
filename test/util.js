/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

module.exports = {
  encode_utf8: encode_utf8,
  encode_latin1: encode_latin1,
  from_hex: from_hex,
  to_hex: to_hex
};

function encode_utf8(s) {
  return encode_latin1(unescape(encodeURIComponent(s)));
}

function encode_latin1(s) {
  var result = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if ((c & 0xff) !== c) throw {message: "Cannot encode string in Latin1", str: s};
    result[i] = (c & 0xff);
  }
  return result;
}

function from_hex(s) {
  var result = new Uint8Array(s.length / 2);
  for (var i = 0; i < s.length / 2; i++) {
    result[i] = parseInt(s.substr(2*i,2),16);
  }
  return result;
}

function to_hex(bs) {
  var encoded = [];

  for (var i = 0; i < bs.length; i++) {
    encoded.push("0123456789abcdef"[(bs[i] >> 4) & 15]);
    encoded.push("0123456789abcdef"[bs[i] & 15]);
  }

  return encoded.join("");
}
