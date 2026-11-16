# Deployment readiness

**Not ready for public deployment.** The existing web service controls local Docker lab routers and relies on localhost-only operation. It has no user authentication or authorization, TLS, CSRF-resistant session security, tenant isolation, production incident response, or production infrastructure. Do not publish its control API or mount the Docker socket into a public service. Docker daemon access is administrative access to the host.

A production design requires a separated, authenticated read-only ingestion service; verified source and target prefixes/ASNs; explicit authorization evidence; secure storage and retention; authenticated alert delivery; monitoring of ingestion lag and gaps; tested failure and restart behavior; and operator approval for any network changes. Router control must stay restricted to the isolated lab. Connectivity in a public collector is a view from its peers, not proof of reachability from all networks.

ML is not ready for production: independently reviewed incidents and benign examples, continuous preceding baselines, causal feature construction, leak-free group/time splits and an untouched test set are needed. A high synthetic score cannot substitute. The guarded historical training command is a prerequisite, not an evaluated or deployed model; history completeness and label quality still require independent review.

Public read-only RIPE RIS Live was selected and a bounded experimental observer exists, but target deployment platform, domain, monitored prefixes/ASNs, authorization source and alert destination have not been supplied. The specified GitHub repository is `AbishakePriyan/BGP_networking_auto_sys`; the connected GitHub app reported no push access.

The prototype now has an on-demand RIPEstat origin validation lookup and a local SQLite candidate history. Neither supplies historical RPKI evidence, a continuous stream across feed gaps, authentication, event retention, or a production notification service.
