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
import { createHash, randomBytes } from "node:crypto";
import { signRecord } from "../lib/record.mjs";
import { leafHash, buildTree, proof, verifyProof } from "../lib/merkle.mjs";

export const fileFingerprint = (bytes) => "0x" + createHash("sha256").update(bytes).digest("hex");
// Leaves are salted (salted-leaf/1): each item gets 16 random bytes, and leaves are ordered by
// their salted hash. Without the salt, the sibling hashes in one item's proof could be matched
// against guessed values to reveal the items next to it. The salt travels only in that item's
// own proof. saltOf(key) can be supplied for reproducible commitments.
export const LEAF_SCHEME = "salted-leaf/1";
const SALT_RE = /^[0-9a-f]{32}$/;
const randomSalt = () => randomBytes(16).toString("hex");
const saltedLeaf = (salt, s) => leafHash(Buffer.from(`${salt}|${s}`, "utf8"));
function commitSalted(keys, saltOf = randomSalt) {
  const entries = keys.map((key) => {
    const salt = saltOf(key);
    if (!SALT_RE.test(salt)) throw new Error("salt must be 32 lowercase hex characters");
    return { key, salt, leaf: saltedLeaf(salt, key) };
  }).sort((a, b) => (a.leaf < b.leaf ? -1 : a.leaf > b.leaf ? 1 : 0));
  const tree = buildTree(entries.map((e) => e.leaf));
  return { root: tree.root, count: entries.length, scheme: LEAF_SCHEME, keys: entries.map((e) => e.key), salts: entries.map((e) => e.salt), tree };
}
const saltedProof = (c, key) => { const i = c.keys.indexOf(key); return i < 0 ? null : { index: i, salt: c.salts[i], branch: proof(c.tree, i) }; };
const saltedMember = (root, count, key, p) => !!p && SALT_RE.test(p.salt) && p.index >= 0 && p.index < count && verifyProof(saltedLeaf(p.salt, key), p.branch, p.index, root);

export function commitVins(vins, { saltOf } = {}) {
  return commitSalted([...new Set(vins)], saltOf);
}
export const vinProof = (c, vin) => saltedProof(c, vin);
export const vinTargeted = (root, count, vin, p) => saltedMember(root, count, vin, p);

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
