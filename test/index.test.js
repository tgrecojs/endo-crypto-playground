import test from "./setup.js";
import crypto from "node:crypto";
import encryptionFns from "../source/index.js";
const isFrozen = (obj) => Object.isFrozen(obj);
test("Array.prototype", async (t) => {
  t.is(isFrozen(Array.prototype), true, "should be frozen.");
});

test("Encryption Fns", async (t) => {
  t.is(
    Object.keys(encryptionFns).length,
    4,
    "must contain the correct number of keys"
  );

  const { encodeMessage, decodeMessage } = encryptionFns;

  const secretMessage = "Hello there, my name is Thomas.";

  const encodedMessage = encodeMessage(secretMessage);
  t.deepEqual(
    decodeMessage.run(encodedMessage),
    secretMessage,
    "decodeMessage function should successfully decrypt the secret message."
  );
});

test("OTP application - using the Compartment API", async (t) => {
  const c1 = new Compartment({ crypto });
  c1.evaluate(`
    const { createCipheriv, randomBytes, createDecipheriv, randomByte } = globalThis.crypto;

    const adts = {
      Fn: (g) => ({
        map: (f) => Fn((x) => f(g(x))),
        chain: (f) => Fn((x) => f(g(x)).run(x)),
        concat: (other) => Fn((x) => g(x).concat(other.run(x))),
        run: g,
      }),
    };

    const { Fn } = adts;

    Fn.ask = Fn((x) => x);
    Fn.of = (x) => Fn(() => x);

    // HMAC - Hash-based Message Authenticaton Code

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
    );

    const handleMessage = () => Fn.of(EncryptedObject); //?

    const handleEncode =
      (message) =>
      ({ encode, inputEncoding, inputDecoding }) =>
        encode.update(message, inputEncoding, inputDecoding) +
        encode.final(inputDecoding);
    const handleAddEncodedMessage = (message) => Fn((env) => ({ ...env, message }));

    const runEncode = (message) =>
      Fn(handleEncode(message)).chain(handleAddEncodedMessage);

    const handleDecode = ({ decode, message, inputDecoding, inputEncoding }) =>
      decode.update(message, inputDecoding, inputEncoding) +
      decode.final(inputEncoding);
      const encryptionFns = {
        createEncryptionObject: runEncryption,
        EncryptedObject,
        encodeMessage: (message) => runEncode(message).run(EncryptedObject),
        decodeMessage: Fn(handleDecode),
      };

  globalThis.encryptionFns = encryptionFns;
  `);

  t.deepEqual(
    c1.globalThis.toString(),
    { crypto, encryptionFns }.toString(),
    `should add the proper functions to the Compartment's globalThis object`
  );
});
