# nacl-browser

NaCl API port for browsers using the [Web Cryptography API](http://www.w3.org/TR/WebCryptoAPI/).

This module is supported by Firefox Nightly (32+) out of the box.

Chrome Canary (37+) works - except the _stream_ module due to a missing AES-CTR
implementation - with experimental Web Platform features enabled.

# example

TODO

# hashing

#### .hash(ArrayBuffer data) → Promise

See `.hash_sha512()` as it is the default hash function.

#### .hash_sha256(ArrayBuffer data) → Promise

Returns a promise that resolves to the SHA-256 message digest corresponding to
the data contained in the given array buffer.

``` js
var msg = "The quick brown fox jumps over the lazy dog";

nacl.hash_sha256(msg).then(function (digest) {
  console.log(digest);
});
```

Output:

```
"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
```

#### .hash_sha512(ArrayBuffer data) → Promise

Returns a promise that resolves to the SHA-512 message digest corresponding to
the data contained in the given array buffer.

``` js
var msg = "The quick brown fox jumps over the lazy dog";

nacl.hash_sha512(msg).then(function (digest) {
  console.log(digest);
});
```

Output:

```
"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
```

# install

With [npm](https://npmjs.org) do:

```
npm install nacl-browser
```

# license

MPL 2.0
