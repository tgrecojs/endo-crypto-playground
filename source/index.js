import { createCipheriv, randomBytes, createDecipheriv } from "node:crypto";

const Fn = (g) => ({
  map: (f) => Fn((x) => f(g(x))),
  chain: (f) => Fn((x) => f(g(x)).run(x)),
  concat: (other) => Fn((x) => g(x).concat(other.run(x))),
  run: g,
});

Fn.ask = Fn((x) => x);
Fn.of = (x) => Fn(() => x);

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
  EncryptedObject: runEncryption("aes256", randomBytes(32), randomBytes(16)),
  encodeMessage: (message) =>
    runEncode(message).run(
      runEncryption("aes256", randomBytes(32), randomBytes(16))
    ),
  decodeMessage: Fn(handleDecode),
};

export default encryptionFns;
