// Tests for the TS port.
// Run: node --experimental-strip-types --test index.test.ts  (Node >=22)
//   or: npx tsx --test index.test.ts
import { test } from "node:test";
import assert from "node:assert";
import { scanObservation, THRESHOLD } from "./index.ts";

const CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";

test("cobalt strike jarm detected", () => {
  const m = scanObservation({ jarm: CS_JARM });
  assert.strictEqual(m[0].family, "Cobalt Strike");
  assert.ok(m[0].confidence >= THRESHOLD);
});

test("clean observation no match", () => {
  assert.strictEqual(scanObservation({ host: "benign", port: 443 }).length, 0);
});

test("weak signals below threshold", () => {
  assert.strictEqual(scanObservation({ port: 50050, uris: ["/submit.php"] }).length, 0);
});

test("ja3 + port + uri scores", () => {
  const m = scanObservation({ ja3: "a0e9f5d64349fb13191bc781f81f42e1", port: 50050, uris: ["/submit.php"] });
  assert.ok(m[0].confidence >= THRESHOLD);
});
