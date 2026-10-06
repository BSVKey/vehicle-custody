// Verify vehicle record chains, update campaigns, incident logs and battery histories.
import { verifyRecord } from "../lib/record.mjs";
import { fileFingerprint, vinTargeted } from "./records.mjs";

// Verify a carmaker campaign against the carmaker's pinned key.
export function verifyCampaign(c, carmakerPub) {
  const v = verifyRecord(c);
  if (!v.ok) return v.reason;
  if (c.kind !== "vehicle.campaign/1") return "not_a_campaign";
  if (v.signer !== carmakerPub) return "campaign_not_signed_by_carmaker";
  return null;
}

// One vehicle's chain.
//   chain:     the records the vehicle uploaded, in order
//   vehicles:  registry() of onboard keys by VIN
//   campaigns: Map campaignId -> { record, proofs: Map vin -> proof }
//   carmakerPub, baseVersion: the version the vehicle left the factory with
//   segments:  optional Map segment -> bytes (the log files themselves, for an incident)
// Returns the software version timeline, the updates, the log coverage and any holes.
export function verifyVehicle(chain, { vin, vehicles, campaigns, carmakerPub, baseVersion, segments }) {
  const problems = [];
  const bad = (reason, detail = {}) => problems.push({ reason, ...detail });
  let version = baseVersion;
  const timeline = [{ from: null, version }];
  const updates = [], holes = [];
  let lastLogEnd = null;

  chain.forEach((r, i) => {
    const v = verifyRecord(r);
    if (!v.ok) { bad(v.reason, { seq: i }); return; }
    const at = r.installedAt ?? r.verifiedAt ?? r.from;
    const kp = vehicles.check(vin, v.signer, at);
    if (kp) bad(kp, { seq: i });
    if (r.vin !== vin) bad("wrong_vehicle", { seq: i });
    if (r.seq !== i || r.prev !== (i ? chain[i - 1].claimId : null)) bad("chain_break", { seq: i });

    if (r.kind === "vehicle.update/1") {
      const c = campaigns.get(r.campaignId);
      const cp = c ? verifyCampaign(c.record, carmakerPub) : "unknown_campaign";
      if (cp) { bad(cp, { seq: i, campaignId: r.campaignId }); return; }
      if (!vinTargeted(c.record.targetsRoot, c.record.targetCount, vin, c.proofs.get(vin))) bad("vehicle_not_targeted", { seq: i, campaignId: r.campaignId });
      if (r.imageHash !== c.record.imageHash) bad("image_not_from_campaign", { seq: i });
      if (r.fromVersion !== version || c.record.fromVersion !== version) bad("version_discontinuity", { seq: i, running: version, stated: r.fromVersion });
      if (r.verifiedAt < c.record.issuedAt) bad("installed_before_campaign_issued", { seq: i });
      updates.push({ campaignId: r.campaignId, result: r.result, at: r.installedAt ?? r.verifiedAt });
      if (r.result === "installed") { version = r.toVersion; timeline.push({ from: r.installedAt, version }); }
    } else if (r.kind === "vehicle.log/1" || r.kind === "vehicle.gap/1") {
      if (lastLogEnd !== null && r.from > lastLogEnd) holes.push({ from: lastLogEnd, to: r.from, minutes: Math.round((r.from - lastLogEnd) / 6000) / 10 });
      if (lastLogEnd !== null && r.from < lastLogEnd) bad("log_overlap", { seq: i });
      lastLogEnd = r.to;
      if (r.kind === "vehicle.log/1" && segments) {
        const bytes = segments.get(r.segment);
        if (!bytes) bad("log_segment_missing", { segment: r.segment });
        else if (fileFingerprint(bytes) !== r.fingerprint || bytes.length !== r.bytes) bad("log_segment_altered", { segment: r.segment });
      }
    }
  });
  for (const h of holes) bad("log_hole", h);
  const gaps = chain.filter((r) => r.kind === "vehicle.gap/1").map((r) => ({ from: r.from, to: r.to, reason: r.reason }));
  return { ok: problems.length === 0, problems, vin, version, timeline, updates, gaps, records: chain.length };
}

// Which software was running at time t, from a verified timeline.
export const softwareAt = (result, t) => result.timeline.filter((x) => x.from === null || x.from <= t).at(-1).version;

// Campaign status across the fleet: what each targeted vehicle has proven so far.
export function campaignReport(campaignId, targets, results) {
  const byVin = new Map(results.map((r) => [r.vin, r]));
  const out = { installed: [], failed: [], noReport: [], invalid: [] };
  for (const vin of targets) {
    const r = byVin.get(vin);
    if (!r) { out.noReport.push(vin); continue; }
    if (!r.ok) { out.invalid.push(vin); continue; }
    const u = r.updates.filter((x) => x.campaignId === campaignId).at(-1);
    (u?.result === "installed" ? out.installed : u ? out.failed : out.noReport).push(vin);
  }
  return out;
}

// A battery's history across companies: each receiver signs, each names the one before, and
// the documents that travel with it are fingerprinted.
export function verifyBattery(history, { companies }) {
  const problems = [];
  history.forEach((h, i) => {
    const v = verifyRecord(h);
    if (!v.ok) { problems.push({ reason: v.reason, index: i }); return; }
    const k = companies.check(h.to, v.signer, h.at);
    if (k) problems.push({ reason: k, index: i, company: h.to });
    if (h.batteryId !== history[0].batteryId) problems.push({ reason: "wrong_battery", index: i });
    if (i && (h.prev !== history[i - 1].claimId || h.from !== history[i - 1].to)) problems.push({ reason: "chain_break", index: i });
  });
  return { ok: problems.length === 0, problems, holder: history.at(-1)?.to, steps: history.map((h) => h.to) };
}
