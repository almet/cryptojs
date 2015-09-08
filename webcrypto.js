function generateAndExportKeypair() {
  return window.crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  true, //whether the key is extractable (i.e. can be used in exportKey)
  ["sign", "verify"])
  .then(key => {
    return window.crypto.subtle.exportKey("jwk", key.privateKey)
     .then(exportedPrivateKey => {
       return {
         privateKey: exportedPrivateKey
       };
     });
  })
  .catch(function(err) {
    console.log(err);
  });
}

function loadKey(rawKey) {
  return window.crypto.subtle.importKey(
    "jwk", rawKey, {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false, //whether the key is extractable (i.e. can be used in exportKey),
    rawKey.key_ops
  )
}

// These two have been generated with the following code:
//
generateAndExportKeypair()
.then(keyData => {
  console.log(keyData);
})
.catch(error => { console.log(error); });

var publicKey = {
}

var privateKey = {
}

// loadKey(publicKey)
// .then(key => { console.log("public key", key); })
// .catch(err => { console.log(err) });
//
// loadKey(privateKey)
// .then(key => { console.log("private key", key); })
// .catch(err => { console.log(err) })
