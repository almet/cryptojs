function generateAndExportKeypair() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"},
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"]
    )
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
    });  
}

function loadKey(rawKey) {
    return window.crypto.subtle.importKey(
        "jwk", rawKey, {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"}
        },
        false, //whether the key is extractable (i.e. can be used in exportKey),
        rawKey.key_ops
    )    
}

// These two have been generated with the following code:
//
// generateAndExportKeypair()
// .then(keyData => {
//    console.log(JSON.stringify(keyData.publicKey));
//    console.log(JSON.stringify(keyData.privateKey));
// });
    
var publicKey = {
    "alg":"RSA-OAEP-256",
    "e":"AQAB",
    "ext":true,
    "key_ops":["encrypt"],
    "kty":"RSA",
    "n":"uAYWnh8s1NgUqlKLjUVtnshWN1yuwzWJKY2iLDKG4BZqt1ViVjlOarFOUDX8ZLmweJKU1snEbMPacQmB2SGw2tM0PbXchO_520qrH9QqVaHX6ONkyeFCcPJLsnRxOxD4hafpkesuExqMSyuSBcYWqTJALNPy_1DI3KpM_cnHprZeZmv4JBZxt0IVgOvVutTYaQkXleIGAIsxrZ__MMyi-4_viZdz8xNg8cE_ce_V58Gj7PWy_ao0oohTc46QlB39k3ivpDh7U3jTCWzj9jCedaVh6C9qAc2cauKp_YYvCHDMxQpFsEPfjR8PsaGjd1sN3J1EZdJMORf09RbKZLtE3w"
}

var privateKey = {
    "alg":"RSA-OAEP-256",
    "d":"iDdBgLP03GxCB71oPR8aQIFsiDhbyHWVXSPQ2kRgX_lX7vMOAmMS75jlLix38hsdTHK8J61cb2IeDLQL4Ky2m5PgxJkcbW6xFSjVOI808wQErQe9ME5EfxRrAeJ9ekpam5yqIO_jwBJTrMTIput1FLL0m_obke-7btPEf8tftL9gHzFjacwslyKvLVC_BRwPOF2qnzgjnRxzXMyK4roqBvChVNfMMwYb7tepdVrZgoVsKGDSjPtoZgndjXA14UWkTTMmuqov1QoiZ260Hkh9XIvZ58HGoecf7wUVuj8fRetBXg50sJBTdaLcKC7ggTFwoFTLezamCx8z--V9adqQyQ",
    "dp":"IO6OsVbsfE0uqnFy0gz6ols8k2zVPPctDXuTo2Kd7tMjWF1DKFQu-jYTyGW-rEMoRFoYe12cAAS6Nmn4bToVu8bq-ccNlIqoe4mbPN_MT-KlpR6oKUy0NnSOwAuZQdhSus37T5OO5HeJKe6TuXzZ20VBe6rwYzziY31nS1FDsUk","dq":"Fp6MO9YWMUiGPOYfSKIZcivBKWEjvrbs8srp1Hn0VDQSr_BzwdsGCqotdk8zjaLdMsrSO0KslMuKJ4xonxFab2BtFVZZigcJCvyFKABZWUOVntKUZl4RMwiUlpyvnvab8ZGSzk0jiaLrOeBXQRg-s1VsHC_RFhj9PKBohurBIlM",
    "e":"AQAB",
    "ext":true,
    "key_ops":["decrypt"],
    "kty":"RSA",
    "n":"uAYWnh8s1NgUqlKLjUVtnshWN1yuwzWJKY2iLDKG4BZqt1ViVjlOarFOUDX8ZLmweJKU1snEbMPacQmB2SGw2tM0PbXchO_520qrH9QqVaHX6ONkyeFCcPJLsnRxOxD4hafpkesuExqMSyuSBcYWqTJALNPy_1DI3KpM_cnHprZeZmv4JBZxt0IVgOvVutTYaQkXleIGAIsxrZ__MMyi-4_viZdz8xNg8cE_ce_V58Gj7PWy_ao0oohTc46QlB39k3ivpDh7U3jTCWzj9jCedaVh6C9qAc2cauKp_YYvCHDMxQpFsEPfjR8PsaGjd1sN3J1EZdJMORf09RbKZLtE3w",
    "p":"8nI23dMwzt9b9Lr166JFHTbH_8957SWdjZAbk9JBfmRA-lLO3st3_Oysu1A0-L-KbMWH80qxp1UhC-kwzqqs1D_rxlAoXS5xto5B3mInrSXyTf_OiSQbAgkBzOEJap79CqknyaxUM_LRgy9EgJ7WiPnApRSmSAuqMrjvDcMe2A0",
    "q":"wk_CEXW_4vbj5OYRNMNd3ZyVkHgrNyfAtB_3Y577itXZi4f-MsNcTXR6S4YNYipxaIcy1yAboemdyLfkvB1yFPfLTxKnMIIIUpnCV10Yt8juMgFiHdBEwo0f4oNp7NBHrpOXtAboPBSzFRegv6fxFkB57hQb-6PmSHgrd1XOCZs",
    "qi":"sAMqaf14UD_536xxtZLMmo3szBNAVX-8nRF4MeKXU-zQp0gl9A58VZXEwmo97BvLErktTyto3srvsloynUEgaF62_B6-cTMVV7wDOWcAGMhCuCt5ZZBTT6Y_vz2WV_0NUrWw24uFS1bFdzTsXtXQgwlXIBWMvW6CevoUtNeiw-M"
}

loadKey(publicKey)
.then(key => { console.log("public key", key); })
.catch(err => { console.log(err) });

loadKey(privateKey)
.then(key => { console.log("private key", key); })
.catch(err => { console.log(err) })
