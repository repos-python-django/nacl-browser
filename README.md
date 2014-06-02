# nacl-browser

NaCl API port for browsers using the [Web Cryptography API](http://www.w3.org/TR/WebCryptoAPI/).

This module is supported by Firefox Nightly (32+) out of the box.

Chrome Canary (37+) works (except the _stream_ module due to a missing AES-CTR
implementation) with experimental Web Platform features enabled.

# example

TODO

# authentication

Secret-key message authentication module.

> Unlike the original NaCl library the default authentication function is
> HMAC-SHA-256 instead of HMAC-SHA-512/256 because unfortunately the Web
> Cryptography API does not provide an implementation of the latter.
>
> While SHA-512/256 can be implemented more efficiently on modern 64-bit CPUs,
> SHA-512 truncated to 256 bits is as safe as SHA-256 as far as the
> cryptography community knows.
>
> Additionally, HMACs are substantially less affected by collisions than their
> underlying hashing algorithms alone.

#### .auth(ArrayBuffer[32] key, ArrayBuffer data) → Promise

See `.auth_hmacsha256()` as it is the default authentication function.

#### .auth_verify(ArrayBuffer[32] key, ArrayBuffer data, ArrayBuffer[32] mac) → Promise

See `.auth_hmacsha256_verify()` as it is the default verification function.

#### .auth_hmacsha256(ArrayBuffer[32] key, ArrayBuffer data) → Promise

Returns a promise that resolves to the HMAC-SHA-256 authenticator corresponding
to the data contained in the given ArrayBuffer under the given key. The key
length must be exactly 32 bytes. The result has a fixed length of 32 bytes.

``` js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

// Generate a random key.
var key = crypto.getRandomValues(new Uint8Array(32));

nacl.auth_hmacsha256(key, data).then(function (mac) {
  console.log(mac);
});
```

Output:

```js
// Note that this MAC will be random because the key used in this example is.
Uint8Array [ 148, 166, 133, 235, 128, 30, 117, 8, 40, 89, ... (and 22 more) ]
```

#### .auth_hmacsha256_verify(ArrayBuffer[32] key, ArrayBuffer data, ArrayBuffer[32] mac) → Promise

Returns a promise that resolves when the given MAC is a valid authenticator
for the data contained in the given ArrayBuffer under the given key. The
promise will be rejected if the MAC is not a valid authenticator.

```js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

// Generate a random key.
var key = crypto.getRandomValues(new Uint8Array(32));

nacl.auth_hmacsha256(key, data).then(function (mac) {
  console.log(mac);

  var promise = nacl.auth_hmacsha256_verify(key, data, mac).then(function () {
    console.log("Given MAC is a valid authenticator!");
  });

  promise.then(function () {
    // Override the key with a new random value.
    key = crypto.getRandomValues(new Uint8Array(32));

    nacl.auth_hmacsha256_verify(key, data, mac).then(function () {
      // We should not get here as the promise
      // (with high probability) must not resolve.
    }, function () {
      console.log("Given MAC is *not* a valid authenticator under the new key!");
    });
  });
});
```

Output:

```js
// Note that this MAC will be random because the key used in this example is.
Uint8Array [ 148, 166, 133, 235, 128, 30, 117, 8, 40, 89, ... (and 22 more) ]

// Verification tests.
"Given MAC is a valid authenticator!"
"Given MAC is *not* a valid authenticator under the new key!"
```


# hashing

Cryptographic hash functions.

#### .hash(ArrayBuffer data) → Promise

See `.hash_sha512()` as it is the default hash function.

#### .hash_sha256(ArrayBuffer data) → Promise

Returns a promise that resolves to the SHA-256 message digest corresponding to
the data contained in the given ArrayBuffer. The result has a fixed lenght of
32 bytes.

``` js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

nacl.hash_sha256(data).then(function (digest) {
  console.log(digest);
});
```

Output:

```js
Uint8Array [ 215, 168, 251, 179, 7, 215, 128, 148, 105, 202, ... (and 22 more) ]
```

#### .hash_sha512(ArrayBuffer data) → Promise

Returns a promise that resolves to the SHA-512 message digest corresponding to
the data contained in the given ArrayBuffer. The result has a fixed length of
64 bytes.

``` js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

nacl.hash_sha512(data).then(function (digest) {
  console.log(digest);
});
```

Output:

```js
Uint8Array [ 7, 229, 71, 217, 88, 111, 106, 115, 247, 63, ... (and 54 more) ]
```

# install

With [npm](https://npmjs.org) do:

```
npm install nacl-browser
```

# license

MPL 2.0
