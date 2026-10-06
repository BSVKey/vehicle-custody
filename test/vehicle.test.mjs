import test from "node:test";
import assert from "node:assert/strict";
import { genKeypair } from "../lib/keys.mjs";
import { signRecord, contentOf, registry } from "../lib/record.mjs";
import { campaign, commitVins, vinProof, onboard, fileFingerprint, batteryHandoff } from "../src/records.mjs";
import { verifyVehicle, softwareAt, campaignReport, verifyBattery } from "../src/verify.mjs";

const MIN = 60000, T0 = Date.parse("2026-09-01T00:00:00Z");
const img = Buffer.from("image 2.0");

function fleet() {
  const maker = genKeypair();
  const vans = ["VIN-A", "VIN-B", "VIN-C"].map((vin) => ({ vin, kp: genKeypair() }));
  const t = commitVins(["VIN-A", "VIN-B"]);
  const c = campaign(maker, { campaignId: "C2", carmaker: "m", imageHash: fileFingerprint(img), fromVersion: "1.0", toVersion: "2.0", targetsRoot: t.root, targetCount: t.count, issuedAt: T0 });
  const campaigns = new Map([["C2", { record: c, proofs: new Map(["VIN-A", "VIN-B", "VIN-C"].map((v) => [v, vinProof(t, v)])) }]]);
  const opts = { vehicles: registry(vans.map((v) => ({ id: v.vin, pub: v.kp.pub }))), campaigns, carmakerPub: maker.pub, baseVersion: "1.0" };
  const segs = new Map();
  const a = onboard("VIN-A", vans[0].kp);
  for (let s = 0; s < 3; s++) { const b = Buffer.from(`seg ${s}`); segs.set(`s${s}`, b); a.log({ segment: `s${s}`, from: T0 + s * 10 * MIN, to: T0 + (s + 1) * 10 * MIN, fingerprint: fileFingerprint(b), bytes: b.length }); }
  a.update({ campaignId: "C2", imageHash: fileFingerprint(img), fromVersion: "1.0", toVersion: "2.0", verifiedAt: T0 + 40 * MIN, installedAt: T0 + 50 * MIN, result: "installed" });
  const b = onboard("VIN-B", vans[1].kp);
  b.update({ campaignId: "C2", imageHash: fileFingerprint(img), fromVersion: "1.0", toVersion: "2.0", verifiedAt: T0 + MIN, installedAt: null, result: "rolled-back" });
  const cc = onboard("VIN-C", vans[2].kp);
  cc.update({ campaignId: "C2", imageHash: fileFingerprint(img), fromVersion: "1.0", toVersion: "2.0", verifiedAt: T0 + MIN, installedAt: T0 + 2 * MIN, result: "installed" });
  return { vans, opts, segs, a, b, cc };
}
const run = (ob, opts, extra = {}) => verifyVehicle(ob.chain, { vin: ob.vin, ...opts, ...extra });

test("an installed update moves the software timeline; logs verify against their files", () => {
  const f = fleet();
  const r = run(f.a, f.opts, { segments: f.segs });
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.equal(softwareAt(r, T0 + 45 * MIN), "1.0");
  assert.equal(softwareAt(r, T0 + 55 * MIN), "2.0");
});

test("campaign report: installed, failed, no report; an untargeted vehicle is invalid", () => {
  const f = fleet();
  const results = [run(f.a, f.opts), run(f.b, f.opts)];
  assert.deepEqual(campaignReport("C2", ["VIN-A", "VIN-B", "VIN-X"], results), { installed: ["VIN-A"], failed: ["VIN-B"], noReport: ["VIN-X"], invalid: [] });
  assert.ok(run(f.cc, f.opts).problems.some((p) => p.reason === "vehicle_not_targeted"));
});

test("deleted, edited, back-dated or foreign-signed records are caught", () => {
  const f = fleet();
  const t = (mutate, extra = {}) => { const ch = structuredClone(f.a.chain); const segs = new Map(f.segs); mutate(ch, segs); return verifyVehicle(ch, { vin: "VIN-A", ...f.opts, segments: segs, ...extra }).problems.map((p) => p.reason); };
  const del = t((ch) => ch.splice(1, 1));
  assert.ok(del.includes("chain_break") && del.includes("log_hole"));
  assert.ok(t((ch, segs) => segs.set("s1", Buffer.from("seg X"))).includes("log_segment_altered"));
  assert.ok(t((ch) => { ch[3] = signRecord(f.vans[0].kp, { ...contentOf(ch[3]), verifiedAt: T0 - MIN }); }).includes("installed_before_campaign_issued"));
  assert.ok(t((ch) => { ch[0] = signRecord(f.vans[1].kp, contentOf(ch[0])); }).includes("signer_not_registered_key"));
  assert.ok(t((ch) => { ch[3] = signRecord(f.vans[0].kp, { ...contentOf(ch[3]), fromVersion: "0.9" }); }).includes("version_discontinuity"));
});

test("a log gap signed by the vehicle is not a hole; an unexplained one is", () => {
  const kp = genKeypair(), ob = onboard("VIN-A", kp);
  ob.log({ segment: "a", from: 0, to: 10, fingerprint: "0x", bytes: 0 });
  ob.gap({ from: 10, to: 20, reason: "restart" });
  ob.log({ segment: "b", from: 20, to: 30, fingerprint: "0x", bytes: 0 });
  ob.log({ segment: "c", from: 40, to: 50, fingerprint: "0x", bytes: 0 });
  const r = verifyVehicle(ob.chain, { vin: "VIN-A", vehicles: registry([{ id: "VIN-A", pub: kp.pub }]), campaigns: new Map(), baseVersion: "1" });
  assert.deepEqual(r.problems.map((p) => [p.reason, p.from, p.to]), [["log_hole", 30, 40]]);
});

test("battery history: chained across companies, forgery caught", () => {
  const cos = ["a", "b", "c"].map((id) => ({ id, kp: genKeypair() }));
  const companies = registry(cos.map((c) => ({ id: c.id, pub: c.kp.pub })));
  const h = [];
  cos.forEach((c, i) => h.push(batteryHandoff(c.kp, { batteryId: "B1", from: i ? cos[i - 1].id : "origin", to: c.id, at: i, docs: [], prev: i ? h[i - 1].claimId : null })));
  assert.equal(verifyBattery(h, { companies }).ok, true);
  const f = structuredClone(h); f[1] = batteryHandoff(genKeypair(), contentOf(h[1]));
  assert.ok(verifyBattery(f, { companies }).problems.some((p) => p.reason === "signer_not_registered_key"));
});

test("log segments can be checked from fingerprints computed where the files are", () => {
  const f = fleet();
  const hashes = new Map([...f.segs].map(([k, b]) => [k, { fingerprint: fileFingerprint(b), bytes: b.length }]));
  assert.equal(verifyVehicle(f.a.chain, { vin: "VIN-A", ...f.opts, segments: hashes }).ok, true);
  hashes.set("s1", { fingerprint: fileFingerprint(Buffer.from("seg X")), bytes: 5 });
  assert.ok(verifyVehicle(f.a.chain, { vin: "VIN-A", ...f.opts, segments: hashes }).problems.some((p) => p.reason === "log_segment_altered"));
});
