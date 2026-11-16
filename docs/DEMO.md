# Faculty demo — current prototype

1. Run `./start.sh` and open the displayed localhost URL. The original lab is separate; see README for versions and known gaps.
2. In Live FRR mode select Initialize / Check Lab and Verify connectivity. Confirm the ping says reachable before proceeding. Start monitoring and choose Alert only.
3. Announce the unauthorized route. Wait for the accepted /25 and alert. Verify connectivity: the attacker Null0 route should blackhole the destination. Show the route and event details; an origin mismatch is a lab rule, not proof of malicious intent.
4. Reset, select Automatic mitigation, then announce again. Show the alert, filter request and verified peer/prefix disappearance. Run Verify connectivity separately and confirm reachable. Do not claim recovery if the ping fails.
5. Select Historical replay, start playback, and inspect timestamp, peer and prefix. Select the 2008 YouTube incident slice or the unlabeled sample. Matched announcements are tied to RIPE’s case study; other records remain unknown. No router is changed, and playback speed is not a real-time detection latency measurement.
6. Reset the live lab after the demonstration. Event history is retained. Use `docker compose stop` when finished if desired.
