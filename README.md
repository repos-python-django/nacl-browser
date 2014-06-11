# nacl-browser

NaCl API port for browsers using the [Web Cryptography API](http://www.w3.org/TR/WebCryptoAPI/).

This module is currently supported by Firefox Nightly (32+) out of the box and
by Chrome Canary (37+) (except the _stream_ module due to a missing AES-CTR
implementation) with experimental Web Platform features enabled.

It merely is a port of the NaCl API and thus can of course not provide the
same guarantees as the native NaCl library itself. The implementation of the
Web Cryptography API and its algorithms might differ between browsers and there
is a good chance that none of the security measures taken by NaCl do apply.

There is however great value in offering the NaCl API instead of the pure Web
Cryptography API due to the former's ease of use. The developer is provided
with a set of secure hash, authentication, and encryption functions and
should not need to think about chosing the right algorithm or the right
encryption mode.

The API should be simple and come without surprises, or unnecessary
flexibility except where strictly necessary. The limited set of available
algorithms is a conservative selection - security is prioritized over
compatibility.

Please take a look at the original [paper introducing NaCl](http://cr.yp.to/highspeed/coolnacl-20120725.pdf).



# secretbox

Secret-key authenticated encryption module.

> The `secretbox()` function is designed to meet the standard notions of
> privacy and authenticity for a secret-key authenticated-encryption scheme
> using nonces.
>
> Note that the length is not hidden. Note also that it is the caller's
> responsibility to ensure the uniqueness of nonces — for example, by using
> nonce 1 for the first message, nonce 2 for the second message, etc. Nonces
> are long enough that randomly generated nonces have negligible risk of
> collision.

### example

```js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);
var nonce = crypto.getRandomValues(new Uint8Array(16));

// Generate a random key.
var key = crypto.getRandomValues(new Uint8Array(32));

// Encrypt.
nacl.secretbox_aes256gcm(key, nonce, data).then(function (enc) {
  console.log(enc);

  // Decrypt.
  nacl.secretbox_aes256gcm_open(key, nonce, enc).then(function (dec) {
    console.log(dec);

    // Override the key with a new random value.
    key = crypto.getRandomValues(new Uint8Array(32));

    // Decrypt again.
    nacl.secretbox_aes256gcm_open(key, nonce, enc).then(function () {
      // We should not get here as the promise
      // (with high probability) must not resolve.
    }, function () {
      console.log("Given data is *not* a valid ciphertext under the new key!");
    });
  });
});
```

Output:

```js
// The message encrypted with the random key and nonce (with the tag at the end).
Uint8Array [ 2, 186, 79, 246, 84, 4, 10, 232, 121, 226, ... (and 49 more) ]

// "The quick brown fox jumps over the lazy dog" as UTF-8 bytes.
Uint8Array [ 84, 104, 101, 32, 113, 117, 105, 99, 107, 32, ... (and 33 more) ]

// Failed decryption with a random key.
"Given data is *not* a valid ciphertext under the new key!"
```

### secretbox()

See `secretbox_aes256gcm()` as it is the default authenticated-encryption
function.

### secretbox_open()

See `secretbox_aes256gcm_open()` as it is the default authenticated-decryption
function.

### secretbox_aes256gcm()

Provides authenticated encryption using the Galois/Counter Mode and AES with
a 256-bit key.

```
Promise secretbox_aes256gcm(
  ArrayBuffer[32] key,
  ArrayBuffer[16] nonce,
  ArrayBuffer data
);
```

#### key
The key used for encryption. Must be exactly 32 bytes.

#### nonce
The unique nonce used for encryption. Must be exactly 16 bytes. It is the
caller's responsibility to ensure its uniqueness — for example, by using nonce
1 for the first message, nonce 2 for the second message, etc. Nonces are long
enough that randomly generated nonces have negligible risk of collision.

#### data
The message that will be encrypted.

#### return value
A promise that resolves to the AES-256-GCM encryption of `data`. The result
will have the same length as `data` plus 16 bytes for the tag that will be
used to verify the ciphertext.

### secretbox_aes256gcm_open()

Decrypts a given ciphertext that was encrypted using the Galois/Counter Mode
and AES with a 256-bit key.

```
Promise secretbox_aes256gcm_open(
  ArrayBuffer[32] key,
  ArrayBuffer[16] nonce,
  ArrayBuffer data
);
```

#### key
The key that was used for encryption. Must be exactly 32 bytes.

#### nonce
The unique nonce used for encryption. Must be exactly 16 bytes. It is the
caller's responsibility to ensure its uniqueness — for example, by using nonce
1 for the first message, nonce 2 for the second message, etc. Nonces are long
enough that randomly generated nonces have negligible risk of collision.

#### data
The ciphertext that will be decrypted.

#### return value
A promise that resolves to the decryption of `data` under the given key and
nonce. The result will have the same length as `data` minus 16 bytes that were
used for the tag. The promise will be rejected if the last 16 bytes of `data`
are not a valid authenticator for the given ciphertext.



# stream

Secret-key encryption module.

> The `stream()` function, viewed as a function of the nonce for a uniform
> random key, is designed to meet the standard notion of unpredictability.
>
> This means that an attacker cannot distinguish this function from a
> uniform random function. Consequently, if a series of messages is
> encrypted by `stream_xor()` _with a different nonce for each message_,
> the ciphertexts are indistinguishable from uniform random strings
> of the same length.
>
> Note that the length is not hidden. Note also that it is the caller's
> responsibility to ensure the uniqueness of nonces — for example, by using
> nonce 1 for the first message, nonce 2 for the second message, etc. Nonces
> are long enough that randomly generated nonces have negligible risk of
> collision.
>
> NaCl does not make any promises regarding the resistance of `stream()` to
> "related-key attacks." It is the caller's responsibility to use proper
> key-derivation functions.

### example

```js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);
var nonce = crypto.getRandomValues(new Uint8Array(16));

// Generate a random key.
var key = crypto.getRandomValues(new Uint8Array(32));

// Encrypt.
nacl.stream_xor(key, nonce, data).then(function (enc) {
  console.log(enc);

  // Decrypt.
  nacl.stream_xor(key, nonce, enc).then(function (dec) {
    console.log(dec);

    // Get the key stream that was used to encrypt.
    nacl.stream(key, nonce, data.byteLength).then(function (key_stream) {
      console.log(key_stream);
    });
  });
});
```

Output:

```js
// The message encrypted with the random key and nonce.
Uint8Array [ 210, 136, 139, 204, 62, 140, 111, 44, 105, 139, ... (and 33 more) ]

// "The quick brown fox jumps over the lazy dog" as UTF-8 bytes.
Uint8Array [ 84, 104, 101, 32, 113, 117, 105, 99, 107, 32, ... (and 33 more) ]

// The key stream that was xor'ed with the plaintext.
// 84 ^ 134 == 210, 104 ^ 224 == 136, 101 ^ 238 == 139, ...
Uint8Array [ 134, 224, 238, 236, 79, 249, 6, 79, 2, 171, ... (and 33 more) ]
```

### stream()

See `stream_aes256ctr()` as it is the default key stream generator.

### stream_xor()

See `stream_aes256ctr_xor()` as it is the default stream cipher.

### stream_aes128ctr()

Generates an AES-128-CTR key stream for a given key and nonce.

```
Promise stream_aes128ctr(
  ArrayBuffer[16] key,
  ArrayBuffer[16] nonce,
  uint length
);
```

#### key
The key used to generate the key stream. Must be exactly 16 bytes.

#### nonce
The unique nonce used to generate the key stream. Must be exactly 16 bytes.
It is the caller's responsibility to ensure its uniqueness — for example, by
using nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible risk of
collision.

#### length
The desired length of the resulting key stream.

#### return value
A promise that resolves to the AES-128-CTR key stream for a given `nonce` under
a given `key`. The result will have the requested `length`.

### stream_aes128ctr_xor()

Provides encryption/decryption using Counter Mode and AES with a 128-bit key.

```
Promise stream_aes128ctr_xor(
  ArrayBuffer[16] key,
  ArrayBuffer[16] nonce,
  ArrayBuffer data
);
```

#### key
The key used for encryption/decryption. Must be exactly 16 bytes.

#### nonce
The unique nonce used to for encryption/decryption. Must be exactly 16 bytes.
It is the caller's responsibility to ensure its uniqueness — for example, by
using nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible risk of
collision.

#### data
The message/ciphertext that will be encrypted/decrypted.

#### return value
A promise that resolves to the AES-128-CTR encryption/decryption of `data`.
The result will have the same length as `data`, and is the bytes of `data`
xor the key stream generated by `stream_aes128ctr()`.

### stream_aes256ctr()

Generates an AES-256-CTR key stream for a given key and nonce.

```
Promise stream_aes256ctr(
  ArrayBuffer[32] key,
  ArrayBuffer[16] nonce,
  uint length
);
```

#### key
The key used to generate the key stream. Must be exactly 32 bytes.

#### nonce
The unique nonce used to generate the key stream. Must be exactly 16 bytes.
It is the caller's responsibility to ensure its uniqueness — for example, by
using nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible risk of
collision.

#### length
The desired length of the resulting key stream.

#### return value
A promise that resolves to the AES-256-CTR key stream for a given `nonce` under
a given `key`. The result will have the requested `length`.

### stream_aes256ctr_xor()

Provides encryption/decryption using Counter Mode and AES with a 256-bit key.

```
Promise stream_aes256ctr_xor(
  ArrayBuffer[32] key,
  ArrayBuffer[16] nonce,
  ArrayBuffer data
);
```

#### key
The key used for encryption/decryption. Must be exactly 32 bytes.

#### nonce
The unique nonce used to for encryption/decryption. Must be exactly 16 bytes.
It is the caller's responsibility to ensure its uniqueness — for example, by
using nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible risk of
collision.

#### data
The message/ciphertext that will be encrypted/decrypted.

#### return value
A promise that resolves to the AES-256-CTR encryption/decryption of `data`.
The result will have the same length as `data`, and is the bytes of `data`
xor the key stream generated by `stream_aes256ctr()`.



# authentication

Secret-key message authentication module.

> The `auth()` function, viewed as a function of the message for a uniform
> random key, is designed to meet the standard notion of unforgeability.
> This means that an attacker cannot find authenticators for any messages
> not authenticated by the sender, even if the attacker has adaptively
> influenced the messages authenticated by the sender.
>
> NaCl does not make any promises regarding "strong" unforgeability;
> perhaps one valid authenticator can be converted into another valid
> authenticator for the same message. NaCl also does not make any
> promises regarding "truncated unforgeability".

### example

```js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

// Generate a random key.
var key = crypto.getRandomValues(new Uint8Array(32));

// Compute an authentication code.
nacl.auth_hmacsha256(key, data).then(function (mac) {
  console.log(mac);

  // Verify.
  nacl.auth_hmacsha256_verify(key, data, mac).then(function () {
    console.log("Given MAC is a valid authenticator!");

    // Override the key with a new random value.
    key = crypto.getRandomValues(new Uint8Array(32));

    // Verify again.
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

### auth()

See `auth_hmacsha256()` as it is the default authentication function.

### auth_verify()

See `auth_hmacsha256_verify()` as it is the default verification function.

### auth_hmacsha256()

Computes a HMAC-SHA-256 message authentication code for a given message.

```
Promise auth_hmacsha256(
  ArrayBuffer[32] key,
  ArrayBuffer data
);
```

#### key
The key used to calculate the authentication code. Must be exactly 32 bytes.

#### data
The message that a MAC is computed for.

#### return value
A promise that resolves to the HMAC-SHA-256 authenticator of `data`. The result
has a fixed length of 32 bytes.

### auth_hmacsha256_verify()

Checks whether a given message authentication code is a valid HMAC-SHA-256
authenticator for a given message.

```
Promise auth_hmacsha256_verify(
  ArrayBuffer[32] key,
  ArrayBuffer data,
  ArrayBuffer[32] mac
);
```

#### key
The key used to calculate the authentication code. Must be exactly 32 bytes.

#### data
The message that `mac` was computed for.

#### mac
The message authentication code for `data`. Must be exactly 32 bytes.

#### return value
A promise that resolves if `mac` is a valid authenticator for `data` under the
given `key`. The promise will be reject if `mac` is not a valid authenticator.



# hashing

Cryptographic hash functions.

### example

``` js
var msg = "The quick brown fox jumps over the lazy dog";
var data = new TextEncoder("utf-8").encode(msg);

nacl.hash(data).then(function (digest) {
  console.log(digest);
});
```

Output:

```js
Uint8Array [ 7, 229, 71, 217, 88, 111, 106, 115, 247, 63, ... (and 54 more) ]
```


### hash()

See `hash_sha512()` as it is the default hash function.

### hash_sha256()

Computes the SHA-256 message digest for a given message.

```
Promise hash_sha256(
  ArrayBuffer data
);
```

#### data
The message that a hash value is computed for.

#### return value
A promise that resolves to the SHA-256 message digest corresponding to `data`.
The result has a fixed length of 32 bytes.

### hash_sha512()

Computes the SHA-512 message digest for a given message.

```
Promise hash_sha512(
  ArrayBuffer data
);
```

#### data
The message that a hash value is computed for.

#### return value
A promise that resolves to the SHA-512 message digest corresponding to `data`.
The result has a fixed length of 64 bytes.



# install

With [npm](https://npmjs.org) do:

```
npm install nacl-browser
```



#notes

Unlike the original NaCl library the default authentication function is
HMAC-SHA-256 instead of HMAC-SHA-512/256 because unfortunately the Web
Cryptography API does not provide an implementation of the latter.

While SHA-512/256 can be implemented more efficiently on modern 64-bit CPUs,
SHA-512 truncated to 256 bits is as safe as SHA-256 as far as the cryptography
community knows. Additionally, HMACs are substantially less affected by
collisions than their underlying hashing algorithms alone.

Unlike the original NaCl library the default authenticated-encryption function
is AES-256-GCM instead of XSalsa20Poly1305 because unfortunately neither
Salsa20 nor Poly1305 is provided by the Web Cryptography API.



# license

MPL 2.0
