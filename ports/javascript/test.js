// Minimal test for the JS port core check. Run: node test.js
import assert from "assert";
import { scanObservation, THRESHOLD } from "./index.js";

const CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";
let n = 0;
function t(name, fn) { fn(); n++; console.log("ok - " + name); }

t("cobalt strike jarm detected", () => {
  const m = scanObservation({ jarm: CS_JARM });
  assert.strictEqual(m[0].family, "Cobalt Strike");
  assert.ok(m[0].confidence >= THRESHOLD);
});

t("clean observation no match", () => {
  const m = scanObservation({ host: "benign", port: 443 });
  assert.strictEqual(m.length, 0);
});

t("weak signals (port + uri only) stay below threshold", () => {
  // port(6) + uri(16) = 22 < 35 — a benign service on 50050 must NOT trip.
  const m = scanObservation({ port: 50050, uris: ["/submit.php"] });
  assert.strictEqual(m.length, 0);
});

t("ja3 indicator scores", () => {
  const m = scanObservation({ ja3: "a0e9f5d64349fb13191bc781f81f42e1", port: 50050, uris: ["/submit.php"] });
  assert.ok(m[0].confidence >= THRESHOLD);
});

console.log(`\n${n} passed`);
