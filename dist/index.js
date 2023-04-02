"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const { decryptSymmetric, encryptSymmetric, generatePublicPrivateKeys, } = require("./crypto");
// User Vault Key, or kind of like password
const userVault = "123456789";
// Generating public, and private keys
const { publicKey, privateKey } = generatePublicPrivateKeys();
// Encrypting private key with userVault
const encryptedPrivateKey = encryptSymmetric(privateKey, userVault);
// // We keep in database publicKey and encryptedPrivateKey
// Save in database public key and encryptedPrivateKey
const user1 = {
    publicKey,
    encryptedPrivateKey,
};
// Opening public-privateKeys
const x = userVault;
const takenEncryptedPrivateKeyFromDatabase = user1.encryptedPrivateKey;
// Checking if entered userVault is valid if not return false if yes return privateKey
const decryptedPrivateKey = decryptSymmetric(takenEncryptedPrivateKeyFromDatabase, x);
if (!decryptedPrivateKey) {
    console.log('DECRYPTION_FAILED');
}
console.log(decryptedPrivateKey, "decryptedPrivateKey");
// Public and privateKey when generating you both of them keeping somewhere, keep public as it is, and encryptPrivate with userVault
// Later encrypting with privateKey we can later encryptand decrypt with only one place and it wil go descendant
// if i encryptSymmetric
//if i encrypted with public key then i have to decrypt it with private key this could be done with encryptAsymetric and DecryptAsymetric
// if i encrypt it userVault then i have to encryptSymteric and DecryptSymetric
// 1 step take userVault from user encryptSymetric encryptPrivateKey,set public and encryptedPrivateKey to database
// 2 step if we want to access some data we decryptSymetric passing encryptedPrivateKeyfrom userTable and setting his userVault, then if it succeeds
// 3 step in this case when we get privateKey(which was decrypted in the second step) we are encrypting asymetric(encryptAsymmetric) passing data that we want to encrypt and that user public key, then setting value to database
// 4 step in this step when we come and want to decrypt the data that was set to database we need to use encryptAsymmetric function passing data that we want to decrypt and user private key, the same user private key which public key was used for encryptAsymmetric
//Summary if we want to have encrypted data in database and the only way to parse it si knowing users vault we can do the following
// Use encryptSymmetric,decryptSymmetric to encrypt and decrypt userVault and private key set it to database for later use
// use encryptAsymmetric,decryptAsymmetric in order to encrypt data with users public key, and decrypt data with users private key and that private key we can get with decryptSymmetric and passing that users encryptedPrivateKey and users vault 
