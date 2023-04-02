const crypto = require("crypto");

const iv = Buffer.from("KoLUnrwQZxgEplhn", "utf-8");

const ENCRYPTION_ALGORITHM = "aes-256-ctr";

export const encryptSymmetric = (data: string, secretKey: string): string => {
 const key = crypto
  .createHash("sha256")
  .update(String(secretKey))
  .digest("base64")
  .substr(0, 32);

 const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
 const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

 return encrypted.toString("hex");
};

export const decryptSymmetric = (
 encryptedData: string,
 secretKey: string
): string | boolean => {
 try {
  const key = crypto
   .createHash("sha256")
   .update(String(secretKey))
   .digest("base64")
   .substr(0, 32);

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);

  const decrypted = Buffer.concat([
   decipher.update(Buffer.from(encryptedData, "hex")),
   decipher.final(),
  ]);

  const decryptedValue = new TextDecoder("utf8", { fatal: true }).decode(
   decrypted
  );

  if (!decryptedValue) {
   return false;
  }
  return decryptedValue;
 } catch (err: any) {
  console.log(err.message, "ERROR DECRYPTION FAILED");
  return false;
 }
};

export const encryptAsymmetric = (
 data: string,
 publicKeyStr: string
): string => {
 const publicKeyObject = crypto.createPublicKey(publicKeyStr);
 publicKeyObject.export({ format: "pem", type: "pkcs1" });
 const encryptedData = crypto.publicEncrypt(
  {
   key: publicKeyObject,
   padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
   oaepHash: "sha256",
  },
  Buffer.from(data)
 );

 return encryptedData.toString("hex");
};

export const decryptAsymmetric = (
 encryptedData: string,
 privateKeyStr: string
): string => {
 try {
  const privateKeyObject = crypto.createPrivateKey(privateKeyStr);
  privateKeyObject.export({ format: "pem", type: "pkcs1" });
  const decryptedData = crypto.privateDecrypt(
   {
    key: privateKeyObject,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
   },
   Buffer.from(encryptedData, "hex")
  );
  return decryptedData.toString();
 } catch (e) {
  console.log("Please enter a valid key", e);
  return "";
 }
};

export const generatePublicPrivateKeys = (): {
 publicKey: string;
 privateKey: string;
} => {
 const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
   type: "spki",
   format: "pem",
  },
  privateKeyEncoding: {
   type: "pkcs8",
   format: "pem",
  },
 });

 return {
  publicKey,
  privateKey,
 };
};
