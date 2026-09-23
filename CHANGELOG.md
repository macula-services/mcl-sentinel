# Changelog

## 0.1.0 (unreleased)

Ported from `hecate-services/hecate-sentinel` (branch
`fix/verified-warden-publisher`, a159d4b) onto `mcl_om` and macula 12.

- **New fact contract.** Canonical macula app topics
  `<realm>/mcl-sentinel/sentinel/watch/{attacker_sighted,attacker_ensnared,campaign_detected,sentinel_checked_in}_v1`
  replace `sentinel/sighting`, `sentinel/ensnare`, `sentinel/campaign` and
  `sentinel/heartbeat`. Keys renamed to one vocabulary (`source_ip`,
  `warden_id`, `label`, `at_ms`); `net_type` is text, where it used to be an
  atom.
- **Hears mcl-warden's contract** (`<realm>/mcl-warden/warden/watch/*_v1`) and
  attributes by the verified publisher only; every report is normalised and
  type-checked before it reaches the evidence.
- **Wardens are keyed by verified node id**, not by the self-asserted label, now
  that warden identities are stored.
- **History is no longer counted twice per restart.** The read model was folded
  by its own boot rebuild and again by the projection evoq replays in full on
  every boot, so each restart added every historical attempt again. The
  projection is gone; the model has one folder.
- **A campaign is announced once, live**, never again on a boot replay.
- **Subscriptions are held per topic**, so losing one does not re-subscribe
  (and double-deliver) the other.
- **Health reports whether the wardens are heard**, instead of a bare `ok`.
- **Geolocation from DB-IP Lite** (CC BY 4.0, mounted, optional), fetched by
  `scripts/fetch-dbip-lite.sh`, replacing MaxMind GeoLite2 files placed by hand.
- **Cut:** the `spartan/broadcast` alert and its digest (no subscriber since the
  society was decommissioned), its per-address alert-dedup snapshots, and the
  older `sentinel/attack` fact (no subscriber).
