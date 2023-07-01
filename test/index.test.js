import test from "./setup.js";
import { makeArchive } from "@endo/compartment-mapper";
import { makeReadPowers } from "@endo/compartment-mapper/node-powers.js";
import crypto from "node:crypto";
import url from "node:url";
import fs from "node:fs";
import { encryptionFns } from "../source/index.js";
const isFrozen = (obj) => Object.isFrozen(obj);
test("Array.prototype", async (t) => {
  t.is(isFrozen(Array.prototype), true, "should be frozen.");
});

const powers = makeReadPowers({ fs, url, crypto });

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

test("powers", async (t) => {
  t.is(powers, {});
});
