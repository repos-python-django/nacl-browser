/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mix(require("./src/hash.js"), module.exports);
mix(require("./src/auth.js"), module.exports);
mix(require("./src/stream.js"), module.exports);

function mix(from, into) {
  for (var key in from) {
    into[key] = from[key];
  }
}
