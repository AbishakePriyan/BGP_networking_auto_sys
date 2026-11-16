# BGPGuard v2 implementation plan

Goal: isolated FRR lab, honest state-driven UI, bounded historical research pipeline.

1. Copy and isolate router configurations; inspect Docker networks and listening ports before starting.
2. Implement validated controller, RIB collector, persistent events, monitoring and independent verification.
3. Build a React frontend driven by backend state with clear live/replay distinction.
4. Exercise baseline, alert-only, reset, automatic mitigation and separate ping.
5. Add a provenance-preserving ingestion and conservative labeling workflow, then replay only verified historical observations.
6. Document reproducibility, limitations and exact verification evidence.
