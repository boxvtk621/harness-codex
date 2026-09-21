#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaBytes = readFileSync(join(here, "transcript-view-v1.schema.json"));
const fixturesBytes = readFileSync(join(here, "transcript-view-v1.fixtures.json"));
const schema = JSON.parse(schemaBytes);
const corpus = JSON.parse(fixturesBytes);
const manifest = JSON.parse(readFileSync(join(here, "transcript-view-v1.manifest.json"), "utf8"));

if (
  manifest.schemaId !== "transcript-view-v1" ||
  manifest.schemaSHA256 !== createHash("sha256").update(schemaBytes).digest("hex") ||
  manifest.fixturesSHA256 !== createHash("sha256").update(fixturesBytes).digest("hex")
) {
  throw new Error("transcript manifest digest mismatch");
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
ajv.addKeyword({
  keyword: "x-utf8MaxBytes",
  type: "string",
  schemaType: "number",
  validate: (limit, value) => Buffer.byteLength(value, "utf8") <= limit,
});
ajv.compile(schema);

let checked = 0;
for (const fixture of corpus.fixtures) {
  const definition = schema.$defs[fixture.contractType];
  if (!definition) throw new Error(`${fixture.name}: missing ${fixture.contractType}`);
  const valid = ajv.compile(definition)(fixture.value);
  if (valid !== fixture.shapeValid) {
    throw new Error(`${fixture.name}: schema result ${valid}, expected ${fixture.shapeValid}`);
  }
  if (valid && fixture.contractType === "projectionFixture") {
    for (const item of [...fixture.value.candidates, ...fixture.value.expected]) {
      const textHash = createHash("sha256").update(item.text, "utf8").digest("hex");
      if (item.textHash !== textHash) {
        throw new Error(`${fixture.name}: textHash is not bound to text`);
      }
    }
  }
  checked++;
}

console.log(JSON.stringify({ schemaId: manifest.schemaId, checked, verdict: "PASS" }));
