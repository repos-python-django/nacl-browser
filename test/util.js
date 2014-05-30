/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

module.exports = {
  abv2hex: abv2hex,
  hex2abv: hex2abv,
  encode: encode
};

// Convert an ArrayBufferView to a hex string.
function abv2hex(abv) {
  var b = new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
  var hex = "";
  for (var i=0; i <b.length; ++i) {
    var zeropad = (b[i] < 0x10) ? "0" : "";
    hex += zeropad + b[i].toString(16);
  }
  return hex;
}

// Convert a hex string to an ArrayBufferView.
function hex2abv(hex) {
  var abv = new Uint8Array(hex.length / 2);
  for (var i=0; i<abv.length; ++i) {
    abv[i] = parseInt(hex.substr(2*i, 2), 16);
  }
  return abv;
}

// Latin-1 encode a given string.
function encode(str) {
  var result = new Uint8Array(str.length);

  for (var i = 0; i < str.length; i++) {
    result[i] = str.charCodeAt(i) & 0xff;
  }

  return result;
}
