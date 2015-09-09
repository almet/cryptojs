/**
 * Generate a keypair and returns it, in its exported form.
 *
 * @returns {Promise} - A promise that will resolve in a JavaScript object with
 * the following attributes:
 *   - {Object} privateKey - The private Key JWK representation.
 *   - {Object} publicKey - The public Key JWK representation.
 **/
function generateAndExportKeypair() {
  return window.crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  },
  true, //whether the key is extractable (i.e. can be used in exportKey)
  ["sign", "verify"])
  .then(key => {
    return window.crypto.subtle.exportKey("jwk", key.publicKey)
     .then(exportedPublicKey => {
       return window.crypto.subtle.exportKey("jwk", key.privateKey)
       .then(exportedPrivateKey => {
         return {
           privateKey: exportedPrivateKey,
           publicKey: exportedPublicKey
         };
       })
     });
  })
  .catch(function(err) {
    console.log(err);
  });
}

/**
 * Load an existing key.
 *
 * @param {Object} rawKey - The key, in its JWK form.
 * @returns {Promise} - A promise that will resolve in the CryptoKey object.
 **/
function loadKey(rawKey) {
  return window.crypto.subtle.importKey(
    "jwk", rawKey, {
      name: "RSASSA-PKCS1-v1_5",
      hash: {name: "SHA-256"}
    },
    false, //whether the key is extractable (i.e. can be used in exportKey),
    rawKey.key_ops
  )
}

/**
 * Sign the given data with the loaded privateKey.
 *
 * @param {String} data - The data, encoded as a string.
 * @param {CryptoKey} privateKey - The loaded CryptoKey object.
 *
 * @returns {Promise} - A promise that will resolve in the base64-encoded
 * signature.
 **/
function sign(data, privateKey) {
  return window.crypto.subtle.sign(
    {
      "name": "RSASSA-PKCS1-v1_5",
    },
    privateKey,
    new TextEncoder("utf-8").encode(data)
  ).then(signature => {
    return arrayBufferToBase64(signature);
  })
  .catch(err => { console.log(err) });
}

/**
 * Verify the given signature validity given the data and public key.
 *
 * @param {String} signature - The signature in base64.
 * @param {String} data - The data, encoded as a string.
 * @param {CryptoKey} publicKey - The loaded CryptoKey object.
 **/
function verify(signature, data, publicKey) {
  return window.crypto.subtle.verify(
    {
        name: "RSASSA-PKCS1-v1_5",
    },
    publicKey,
    base64ToArrayBuffer(signature),
    new TextEncoder("utf-8").encode(data)
  );
}

/**
 * Convert a base64 String into an Array Buffer.
 *
 * @param {String} base64 - A base64 string.
 * @returns {ArrayBuffer} - The Array Buffer representation of the given
 * string.
 **/
function base64ToArrayBuffer(base64) {
  var binary_string =  window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array( len );
  for (var i = 0; i < len; i++)        {
      bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert an Array Buffer into a base64 String.
 *
 * @param {ArrayBuffer} buffer - The Array buffer to convert.
 * @returns {String} - The base64 representation of the given Array
 * Buffer.
 **/
function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa(binary);
}

/**
 * Sign the given text with the given privateKey.
 *
 * @param {String} text - The text to sign.
 * @param {Object} privateKey - The private key to use in its JWK form.
 * @returns {Promise} - A Promise which resolves in the base64-encoded signature.
 **/
function createSignature(text, privateKey) {
  return loadKey(privateKey)
  .then(loadedPrivateKey => {
    return sign(text, loadedPrivateKey)
  });
}

/**
 * Verify the given signature is valid for the given text and public key.
 *
 * @param {String} signature - The base64-encoded signature to validate.
 * @param {String} text - The text that has been signed.
 * @param {Object} publicKey - The public key to use in its JWK form.
 * @returns {Promise} - A Promise which resolves in a boolean flag, stating if
 * the signature is valid or not.
 **/
function verifySignature(signature, text, publicKey) {
  return loadKey(publicKey)
  .then(loadedPublicKey => {
    return verify(signature, text, loadedPublicKey)
  });
}


