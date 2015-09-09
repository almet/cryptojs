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


// Generate the following keys with this quick code snippet.
// generateAndExportKeypair()
// .then(keyData => {
//   console.log(keyData);
//    console.log(JSON.stringify(keyData.publicKey));
//    console.log(JSON.stringify(keyData.privateKey));
// })
// .catch(error => { console.log(error); });

var publicKey = {
  "alg":"RS256",
  "e":"AQAB",
  "ext":true,
  "key_ops":["verify"],
  "kty":"RSA",
  "n":"w3GOsTNvBN2J3B4SbUlnZJExvuIONYZoIQV7ednv51Gbi9fzEf_gU-4Dh-DdHsBVahhJsirnGg5TI5E2MTyNk_ZQniAE643kFSn_8bZ8FW0_1GP0XkqTR0rQJgSGdycjx6hFpo-3b0t1qifBBxio3SvxAt9lmLU0PlFZYiXrd4YhkHZ5i70bkIa3iJ9F9oJNj7Q7zs43xJ5x7_XTL7nn84z0qaC-VtJyU-SeEi_p5qnhGvWbb4HNiQyK_-Ww1giEUUscd86NkmlqJ8d58ySayVSN2zbKfbWoXNXyMjX8MhiAGUpP5hYmWv_euysDbTS8KSdszEIhA3MNsdxqua8CMw"}

var privateKey = {
  "alg":"RS256",
  "e":"AQAB",
  "ext":true,
  "key_ops":["sign"],
  "kty":"RSA",
  "d":"OklujchSDrhnOd86DZ-7lxF6LXxLUokwGtEAvxlQ48LBydXwZujRpRYxtV9JcrdXgdmWeO00mN-2yb-v0sVFT-BAsLfJ39okMG-jJhoPLXC0fYoFwe0puTRFmWD2HSjuEchMZV0tDqMJh2JtvckL61IEgZ_QM9euqfsm1g-LBszTNAUIVpdkQASfSXZGTOplY15YzmBdbel8rUKvRB1okwdeIdm34CBIBGML58Rd8pkpaLD6aFmOqyDm83tGy5j8uzUtb5eBd3VmEDyJNMQ1YOZMqWOZEtYEhsFdjQfjkHf2lTCvVRKUEA-tg8dhal62vU1Qvc6jUEmP6fzbvJDMGQ",
  "dp":"5DbIeA-zGGF3FOD_4Zgyl3F5zz7jussirx9Mo3VMlD1uvu33VkPwFp2Eow30J5dw1I1JIkO3mCNVD-4A2L1Bv2NcgynjblNA48tvrPtV7NYUq-Hb9JQg3SkyIDAA5Rh0jz_SFo98cZS_PP27CmecOpMxpQvbhnmzZh288bxbTME",
  "dq":"xzGYkAvna0_OCS3MtLt7PXxwWEop02XHFz9UCekYmx6WTIt06MNgtpRpj07WLju7KUcCy4Xy2Wxe6XH-cDaqIr9si4O6kry9jkRnX8qnM_Oyd7QqIQZ8O-JtrEgApBa-XOkVnOv_pQhxeVrgxLkYDOfxMvu_zsm8-UMJ37025kk",
  "n":"w3GOsTNvBN2J3B4SbUlnZJExvuIONYZoIQV7ednv51Gbi9fzEf_gU-4Dh-DdHsBVahhJsirnGg5TI5E2MTyNk_ZQniAE643kFSn_8bZ8FW0_1GP0XkqTR0rQJgSGdycjx6hFpo-3b0t1qifBBxio3SvxAt9lmLU0PlFZYiXrd4YhkHZ5i70bkIa3iJ9F9oJNj7Q7zs43xJ5x7_XTL7nn84z0qaC-VtJyU-SeEi_p5qnhGvWbb4HNiQyK_-Ww1giEUUscd86NkmlqJ8d58ySayVSN2zbKfbWoXNXyMjX8MhiAGUpP5hYmWv_euysDbTS8KSdszEIhA3MNsdxqua8CMw",
  "p":"62a_ZiY1q19o2Xsm4mCnSprrkRYwUzkLITVtJ4a8q4YKK9MXazCyz4LJAvnXFeaywH31v3SYxWDymprrE0Sis8FzOsFtwa_dJstomZsOR7xxundL1u9CqhsCS052D3IEajIINou2gvAk8mKaXiIQxTQTDROqNAvWWnPLtv704kU",
  "q":"1Iu2DKfz03t2ZIPvI23Rp9YtZrGiID3_SZE-iszG8vFASLKY96YCm-fK7nqyNmRwQeWs0RrAfk31yZ6RW0SD8ub45Kzyxct776tlXf0x5M2ghDQ5gct4svxsB6BKExH_2Tfpe_9Air7bHLX31DoSdt87P4ZOK1qYXLJni5d11hc",
  "qi":"Y16hgpV-Cr4IujX0C_1NxeZa_HyDapgRcglGbn3PgJIWvSg0EkPJtHa7WYZEP-mD8b-BVGDFD8uimadFAEPU23j_AUn0scq-fPXwTDFHmv8QgadF4oAcR5Ji1b5TTuhFpW136tOGme7mBX4UzxaPSIQ458sk6dAt67egAZkz4wU"}


// And this is where the fun happens !

var text = "this is something to sign";

createSignature(text, privateKey)
.then(signature => {
  console.log(signature);
  return verifySignature(signature, text, publicKey);
})
.then(isValid => {
  console.log('Is the signature valid?', isValid);
})
.catch(err => { console.log(err) })
