# Copilot instructions

- Treat ThreatScope as a defensive, local learning lab. Keep scanner traffic confined to the sample target and the private Docker `lab` network.
- Use generated fixtures for detection examples. Keep public-data results and their label limitations separate from synthetic benchmark claims.
- Preserve per-rule alerts when changing the scan → authentication → web egress correlation; retain source-IP, ordering, duplicate, and time-window safeguards.
- Keep the Sigma subset and Python engine semantics explicit. Update `docs/SIGMA.md` when field mappings or time-window behavior changes.
- Run the relevant pytest checks and `python -m threatscope.evaluate`; Sigma rule changes also need the pinned Sigma CLI CI check.
- Keep demo IPs within RFC 5737 documentation ranges and avoid real hostnames, credentials, or public scanning targets.
