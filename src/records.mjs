// Signed records for vehicle software updates, incident logs and battery history.
//
//   vehicle.campaign/1  signed by the CARMAKER: an update image (its hash), the version it moves
//                       from and to, and a Merkle root over the VINs it targets.
//   vehicle.update/1    signed by the VEHICLE's onboard key: received the image, verified it,
//                       and installed it (or failed and rolled back), with times.
//   vehicle.log/1       signed by the vehicle as each log segment is closed: a fingerprint of
//                       the segment bytes and the time it covers.
//   vehicle.gap/1       signed by the vehicle: the logger was offline from..to, and why.
//   battery.handoff/1   signed by each company receiving a battery or material batch, with
//                       fingerprints of the documents that came with it.
//
// Each vehicle's records form ONE chain (seq + prev), signed onboard as they happen and
// uploaded whenever the vehicle is next connected. A deleted, reordered or back-dated record
// breaks the chain.
import { createHash } from "node:crypto";
import { signRecord } from "../lib/record.mjs";
import { leafHash, buildTree, proof, verifyProof } from "../lib/merkle.mjs";

export const fileFingerprint = (bytes) => "0x" + createHash("sha256").update(bytes).digest("hex");
const leaf = (s) => leafHash(Buffer.from(s, "utf8"));

export function commitVins(vins) {
  const keys = [...new Set(vins)].sort();
  const tree = buildTree(keys.map(leaf));
  return { root: tree.root, count: keys.length, keys, tree };
}
export const vinProof = (c, vin) => { const i = c.keys.indexOf(vin); return i < 0 ? null : { index: i, branch: proof(c.tree, i) }; };
export const vinTargeted = (root, count, vin, p) => !!p && p.index >= 0 && p.index < count && verifyProof(leaf(vin), p.branch, p.index, root);

export const campaign = (kp, { campaignId, carmaker, imageHash, fromVersion, toVersion, targetsRoot, targetCount, issuedAt }) =>
  signRecord(kp, { kind: "vehicle.campaign/1", campaignId, carmaker, imageHash, fromVersion, toVersion, targetsRoot, targetCount, issuedAt });

// A vehicle's onboard signer: keeps its own chain and signs each record as it happens.
export function onboard(vin, kp) {
  const chain = [];
  const add = (kind, fields) => {
    const last = chain.at(-1);
    const rec = signRecord(kp, { kind, vin, seq: chain.length, prev: last ? last.claimId : null, ...fields });
    chain.push(rec);
    return rec;
  };
  return {
    vin, chain,
    update: (f) => add("vehicle.update/1", f),            // { campaignId, imageHash, fromVersion, toVersion, verifiedAt, installedAt, result }
    log: (f) => add("vehicle.log/1", f),                  // { segment, from, to, fingerprint, bytes }
    gap: (f) => add("vehicle.gap/1", f),                  // { from, to, reason }
  };
}

export const batteryHandoff = (kp, { batteryId, from, to, at, docs, stateOfHealth = null, prev = null }) =>
  signRecord(kp, { kind: "battery.handoff/1", batteryId, from, to, at, docs, stateOfHealth, prev });
