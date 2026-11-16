# BGPGuard v2 — work in progress

This separate WSL2 project is an experimental upgrade of BGPGuard. The original `~/BGPGuard_Working_Lab` was not changed. **The requested upgrade is not complete.** The live route-control demonstration and a small historical replay work; a defensible independently evaluated real-data model is not available. Do not present this as a finished project or claim recovered connectivity.

## Start in Ubuntu 24.04

Docker Desktop must be running with Ubuntu 24.04 WSL integration enabled. This checkout has a local Python environment and Node 22.17.0 under `.tools`. From WSL:

```bash
cd ~/BGPGuard_v2
./start.sh
```

Open http://127.0.0.1:5173. The script checks Docker, occupied host ports, and existing Docker subnet overlap before starting the distinct `bgpguard-v2` Compose project, FastAPI on 127.0.0.1:8000, and Vite on 127.0.0.1:5173. Ctrl-C stops the two web processes; lab containers remain running. To stop only this lab: `docker compose stop`. The original lab uses different container names and subnet. A fresh machine also needs Python 3.12, a venv populated with `pip install -r requirements.lock`, Node 22.17.0 or a compatible later Node, and `npm ci` in frontend; edit the PATH in start.sh if Node is installed elsewhere.

Legacy CLI copies remain available in this directory: `.venv/bin/python lab.py status`, `paths`, `attack-on`, `attack-off`, `ping`, `reset`, `filters`. They control **v2 only**. Avoid running the old CLI monitor concurrently with the web monitor. Reset withdraws the v2 announcement, clears v2 runtime filter lists, and retains event history in `logs/events.sqlite3`.

## Observed verification

On 2026-11-15 with Docker Desktop 29.9.2, Compose 5.6.1, WSL Ubuntu 24.04 / Python 3.12.3, `tests/live_scenario.py` passed baseline ping → alert-only /25 accepted and alert → attack ping unreachable → reset → automatic filter verification → recovered ping reachable. The v2 network is internal `10.199.0.0/16`, with router peers `10.199.0.2`, `.3`, `.4` and destination `10.199.113.10`; R1 advertises `10.199.113.0/24`, and R3 announces `10.199.113.0/25`. This private aggregate is necessary because Docker Desktop's internal bridge drops packets addressed outside its configured subnet. The original `172.30.77.0/24` lab was not reconfigured, and its own test ping failed in a read-only check. The v2 containers were reset after the test.

The UI uses observed RIB snapshots, not packet capture or UPDATE streams. Route animations illustrate state, not packets. Null0 is blackholing, not interception. The authorization rule is used live; the copied Random Forest artifact was trained on synthetic labels directly derived from mismatch and has no credible real-world performance. It is not used by this backend. Current state is memory-resident and may be stale after monitoring stops or the backend restarts; event history is persistent. This prototype does not yet provide reliable run/active-alert accounting or complete action reconciliation on restart.

## Bounded real observation collection

```bash
.venv/bin/python pipeline/collect.py --url https://data.ris.ripe.net/rrc00/2008.02/updates.20080224.1800.gz --collector rrc00 --prefix 195.251.5.0/24 --max-mb 1
```

The checked sample contains 13 deduplicated matching records, all unknown. It is a parser exercise, **not a labeled incident**. A HEAD size check precedes download; cache, resume and SHA-256 manifest are under `data/cache`. The command overwrites `data/observations.jsonl`, so save that output before another export. Cache validation currently checks size and recomputes a checksum but does not compare with an authoritative published checksum. The prefix may be unrelated to any incident. The unlabeled sample has no RIB baseline; the separate incident slice has an earlier RIB with an intervening update gap. More work is required to validate event evidence and timestamp windows, distinguish leaks, label conservatively, split by incident/time, implement causal features and evaluate a model. Select Historical replay in the UI, choose either the unlabeled sample or the documented 2008 YouTube incident slice, then Start/Pause and select a playback speed. The incident slice can be rebuilt with `.venv/bin/python pipeline/youtube_2008.py`. See `docs/DATASET_CARD.md` for the evidence and missing baseline interval. Playback never changes a router. A guarded historical training command exists, but no eligible real-data model has been trained. See `docs/TRAINING_AUDIT.md` for its strict input requirements.

RIPE documents MRT dumps and updates at https://ris.ripe.net/docs/mrt/; BGPKIT parser API is at https://github.com/bgpkit/pybgpkit. RouteViews archives and API, CAIDA BGPStream and Cloudflare anomaly records are useful further sources; provider detections are candidate evidence, not confirmed labels.

## Tests and current limitations

```bash
.venv/bin/python -m pytest tests -q
(cd frontend && npm run build)
```

The test suite is small; it does not yet cover all requested parsing, action, state, temporal leakage, or split cases. Simulated response, independently reviewed negative labels, multi-incident training, rich evaluation, run history, fault injection, reconnection reconciliation, model schema integration, and a complete presentation guide remain outstanding. API controls are for localhost development; do not expose the API to a network or treat it as production hardened. Full disconnected Docker/WebSocket and failed-mitigation tests have not been completed.

## Training report

See `docs/TRAINING_AUDIT.md` or `/api/model/audit`. The existing and reproduced models are synthetic demonstrations with target leakage, not deployable evidence. The real observations have not been used to train a model.

## Public read-only feed (experimental)

Select **Public feed**, enter an IPv4 or IPv6 network to watch, and start it. The service subscribes to RIPE RIS Live updates for that network and more-specifics, then verifies each observation is within the selected network. Updates are collector views, not a complete Internet routing table. An optional comma-separated expected-origin list requires an operator-provided evidence source. A different origin is an `origin_mismatch` candidate, not proof of a hijack; AS-path ambiguity and withdrawals remain unknown. The expected-origin baseline applies to all subnets and is not an RPKI max-length validation. No public feed action modifies any router.

The feed has a bounded in-memory buffer of 100 observations. Origin-mismatch candidates and their collector, peer, AS path and message timestamps are stored in SQLite (`logs/events.sqlite3`); duplicates are grouped and review status is retained across restarts. Candidate counts are collector observations, not independent incidents, and “Mark reviewed” does not establish routing recovery. Missed updates are not recovered after disconnect; a gap counter and last-message time expose some coverage limitations. The history has no automatic retention limit yet. It does not yet implement multi-peer confirmation, RPKI validation, notification delivery, robust health supervision, or verified production deployment. Start/stop and origin configuration are local to one backend process. A prefix must be at least /8 IPv4 or /16 IPv6.

Candidate review supports an on-demand **current** RIPEstat RPKI validation for the candidate prefix and origin. It reports RIPEstat's response and retrieval time separately from the event; a current validation is not proof of malicious intent, historical validity, or recovery. The lookup can fail or return unknown and does not trigger filtering. See `https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation` for the provider's status definitions.
