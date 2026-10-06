# Vehicle Custody

Verifiable evidence of vehicle software updates, incident logs and battery history.

Vehicles are connected only some of the time. Here the carmaker signs each update
campaign, and each vehicle signs, with its own onboard key, every update it installs and
every log segment it closes, as it happens. The records form one chain per vehicle and are
uploaded whenever the vehicle next connects. After an incident, anyone with the records
and the log files can check which software was running and whether the logs are intact.

```
npm test          # offline, zero dependencies
node demo.mjs     # an update campaign across 8 vans, a collision, a battery's history
```

## What the demo shows

```
Campaign DA-4.2.0 (4.1.3 -> 4.2.0), signed by the carmaker, 8 vans targeted
  installed, proven by the van's own signature: 6
  failed and rolled back: van-05
  no report yet: van-08
  van-07 reported three days after issue, from records signed onboard at install time

Collision: van-03
  van-03 records verified with the log files: PASS (38 records, chain unbroken)
  software running at the time: 4.2.0
  logger offline: 4 min, logger restart (signed by the van, not hidden)

Tampering:
  the log segment covering the collision is deleted        caught
  the collision segment's bytes are edited                 caught
  install date moved to after the collision, re-signed     caught
  records re-signed with another van's key                 caught
  van reports an image the carmaker never released         caught
  campaign forged by someone other than the carmaker       caught

Battery PACK-77-0412: cell-maker -> pack-assembler -> carmaker -> fleet-operator -> recycler: PASS
  fleet operator record re-signed by a forger              caught
```

All vehicles, images, logs and companies in the demo are sample data.

## Records

| Record | Signed by | Says |
|---|---|---|
| `vehicle.campaign/1` | the carmaker | an update image (its hash), the version it moves from and to, and a Merkle root over the VINs it targets |
| `vehicle.update/1` | the vehicle's onboard key | received the image, verified it, installed it or rolled back, with times |
| `vehicle.log/1` | the vehicle | a fingerprint of a closed log segment, its size and the time it covers |
| `vehicle.gap/1` | the vehicle | the logger was offline from..to, and why |
| `battery.handoff/1` | each company receiving a battery | received this battery from that company, with fingerprints of its documents |

Each vehicle's records carry a sequence number and the previous record's id, so a deleted,
reordered or back-dated record breaks the chain. All records use canonical JSON, a SHA-256
content id and an Ed25519 signature.

## Rules the verifier applies

- Every vehicle record is signed by that vehicle's registered key; campaigns by the
  carmaker's pinned key.
- An update must name a campaign the carmaker signed, for a vehicle in its target set,
  with the campaign's image, continuing from the version actually running, and not before
  the campaign was issued.
- Log segments and gap records must cover time continuously; an unexplained hole is
  flagged. Given the log files, each must match its signed fingerprint and size.
- `softwareAt` gives the version running at any moment; `campaignReport` gives installed,
  failed and not-yet-reported vehicles for a campaign.
- Battery handoffs must chain from company to company, each signed by the receiver.

Limit: deleting the newest records before they are uploaded is only detectable against a
later record or a receipt for the chain head taken at upload.

## Scope

Evidence tooling, not a type-approved update management system. It records what vehicles
and carmakers signed; it does not control the vehicle or its software.

## License

Apache License 2.0. Copyright 2026 Embryo Space Inc. (DBA BSVKey).
