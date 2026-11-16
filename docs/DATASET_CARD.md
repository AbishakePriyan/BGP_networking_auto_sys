# Dataset card — preliminary parser sample

Source: RIPE RIS rrc00, 2008-02-24 18:00 UTC MRT UPDATE file; exact URL, byte count and SHA-256 in `data/cache/*.manifest.json`. One selected prefix, 195.251.5.0/24, was chosen solely to validate parsing. Thirteen matching deduplicated peer observations were exported. All labels are unknown; there is no verified incident, baseline RIB, ownership claim, or training set. Multiple peer observations are not independent incidents. Withdrawals have no fabricated origin or AS path. This sample is unsuitable for supervised evaluation or accuracy claims.

## Bounded documented incident slice

`pipeline/youtube_2008.py` downloads one preceding RRC00 RIB at 15:59 UTC and five UPDATE files covering 18:40–19:05 UTC on 24 February 2008. The archived compressed files total roughly 15 MB and each has a cache manifest with SHA-256. RIPE's [case study](https://www.ripe.net/about-us/news/youtube-hijacking-a-ripe-ncc-ris-case-study/) identifies an unauthorized AS17557 announcement of 208.65.153.0/24 from 18:47 UTC; a YouTube AS36561 /22 is the legitimate covering route. This export contains 38 collector observations: 26 announcements match the stated /24, single origin and reported window; the other 12 are unknown. Collector copies are not independent incidents. `incident_match` describes agreement with documented evidence, not a claim that every observation is an independent incident or a complete account of the event. Withdrawals, other prefixes, origins and times are unknown, not negatives.

The 15:59 snapshot and 18:40 updates do **not** establish continuous state between those times; missing updates and a single collector limit inference. It is one event, with no independent train/test split, no reviewed benign examples, and no defensible model evaluation. Replay is illustrative and changes no router. Rebuild with `.venv/bin/python pipeline/youtube_2008.py`; this overwrites the generated incident export and retains cached MRT files.

For RIB entries, `timestamp_utc` is the snapshot filename time (15:59 UTC), used for playback; `mrt_entry_timestamp_utc` retains the entry timestamp from MRT. It is not a precise time at which the collector learned every route in the dump. UPDATE records retain their MRT timestamps.

The generated historical feature export is `data/features/youtube_2008.jsonl`, with checksum and class counts in the adjacent manifest. It is not a training set: it contains one incident, no reviewed negatives and incomplete preceding history. See TRAINING_AUDIT.md for the versioned feature contract and limitations.
