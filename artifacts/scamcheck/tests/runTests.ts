import { runTests } from "../src/lib/scamAnalyzer.ts";
import { runFeatureTests } from "./featureTests.ts";

const results = [...runTests(), ...runFeatureTests()];
let pass = 0, fail = 0;
for (const r of results) {
  const status = r.passed ? "PASS" : "FAIL";
  if (r.passed) pass++; else fail++;
  console.log(status + " | expected=" + r.expected + " actual=" + r.actual + " score=" + r.score + " | " + r.label);
  if (!r.passed) console.log("   text: " + r.text);
}
console.log("\n" + pass + " passed, " + fail + " failed out of " + results.length);
process.exit(fail > 0 ? 1 : 0);
