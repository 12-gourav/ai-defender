// Sign an engine manifest with the release key. Run by the release owner on a machine that
// holds the key; the key file is never committed or packaged.
//
// Usage:
//   node scripts/sign-engine-manifest.mjs --manifest ../dist/engine-linux-x64/engine-manifest.json \
//        --key /secure/agentguard-release-ed25519.pem
// Generate a release key once (store it offline):
//   openssl genpkey -algorithm ed25519 -out agentguard-release-ed25519.pem
//   node scripts/sign-engine-manifest.mjs --print-public-key --key agentguard-release-ed25519.pem
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: { manifest: { type: "string" }, key: { type: "string" }, "print-public-key": { type: "boolean" } },
  strict: true,
});
if (!values.key) {
  console.error("usage: sign-engine-manifest.mjs --key <pem> (--manifest <file> | --print-public-key)");
  process.exit(2);
}
const privateKey = createPrivateKey(readFileSync(values.key));
if (privateKey.asymmetricKeyType !== "ed25519") {
  console.error("the release key must be Ed25519");
  process.exit(1);
}
const raw = Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url");
const keyId = createHash("sha256").update("agentguard.release-key-id.v1\u0000").update(raw).digest("hex").slice(0, 32);
if (values["print-public-key"]) {
  console.log(JSON.stringify({ publicKey: raw.toString("hex"), keyId }));
  process.exit(0);
}
const canonical = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(canonical).join(",")}]`
      : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
const manifest = JSON.parse(readFileSync(values.manifest, "utf8"));
const message = Buffer.concat([Buffer.from("agentguard.engine-manifest.v1\u0000"), Buffer.from(canonical(manifest.body))]);
manifest.key_id = keyId;
manifest.signature = sign(null, message, privateKey).toString("base64");
writeFileSync(values.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`signed ${values.manifest} with key ${keyId}`);
