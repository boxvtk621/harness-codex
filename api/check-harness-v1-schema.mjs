#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, "harness-v1.schema.json"), "utf8"));
const corpus = JSON.parse(readFileSync(join(here, "harness-v1.fixtures.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addKeyword({
  keyword: "x-utf8MaxBytes",
  type: "string",
  schemaType: "number",
  validate: (limit, value) => Buffer.byteLength(value, "utf8") <= limit,
});
ajv.compile(schema);

let checked = 0;
for (const fixture of corpus.fixtures) {
  if (!("value" in fixture) || fixture.authoritativeOutcome) continue;
  const definition = schema.$defs[fixture.wireType];
  if (!definition) throw new Error(`${fixture.name}: missing schema definition ${fixture.wireType}`);
  const valid = ajv.compile(definition)(fixture.value);
  const expected = fixture.schemaValid ?? fixture.shapeValid;
  if (valid !== expected) throw new Error(`${fixture.name}: schema result ${valid}, expected ${expected}`);
  checked++;
}
console.log(JSON.stringify({ draft: schema.$schema, checked, verdict: "PASS" }));
