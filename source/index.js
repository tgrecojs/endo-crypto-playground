import crypto from "node:crypto";
import { Fn } from "./ADTs.js";

// HMAC - Hash-based Message Authenticaton Code

const { createCipheriv, randomBytes, createDecipheriv } = crypto;

const runEncryption = (
  algorithm = "aes256",
  key,
  initializationVector,
  inputEcoding = "utf-8",
  inputDecoding = "hex"
) => ({
  encode: createCipheriv(algorithm, key, initializationVector),
  inputEcoding,
  inputDecoding,
  decode: createDecipheriv(algorithm, key, initializationVector),
});

const EncryptedObject = runEncryption(
  "aes256",
  randomBytes(32),
  randomBytes(16)
); //?

const handleMessage = () => Fn.of(EncryptedObject); //?
handleMessage("thomas"); //?

const handleEncode =
  (message) =>
  ({ encode, inputEncoding, inputDecoding }) =>
    encode.update(message, inputEncoding, inputDecoding) +
    encode.final(inputDecoding);
const handleAddEncodedMessage = (message) => Fn((env) => ({ ...env, message }));

const runEncode = (message) =>
  Fn(handleEncode(message)).chain(handleAddEncodedMessage); //?

const handleDecode = ({ decode, message, inputDecoding, inputEncoding }) =>
  decode.update(message, inputDecoding, inputEncoding) +
  decode.final(inputEncoding);

const encryptionFns = {
  createEncryptionObject: runEncryption,
  EncryptedObject,
  encodeMessage: (message) => runEncode(message).run(EncryptedObject),
  decodeMessage: Fn(handleDecode),
};

export { encryptionFns };
