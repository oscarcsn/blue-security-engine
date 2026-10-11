# Security policy

This policy covers the BSE Python package in `src/bse`, its demo and package
tests. The current development version is `0.1.0`. The separate laboratory
supervisor and its integration suites are not shipped by this package.

## Trust boundaries

The application is responsible for authenticating users, authorizing tenant
and session selection, limiting input sizes, and selecting trusted directories
and HMAC keys. BSE does not turn arbitrary Python objects into safe input:
session-store copying may invoke their Python copy behavior. Use application
validated data, not objects obtained by executing untrusted code.

Record contents, identifiers, composite-key components and manifest payloads
may be malformed or attacker-controlled at an application boundary. Sandbox
configuration and filesystem ancestry remain trusted caller responsibilities.
A compromised host, HMAC key or execution supervisor is outside the protection
provided by these helpers.

## Properties to review

- Graph validation rejects missing, null, blank and duplicate normalized node
  identifiers and reports cycles without recursive graph traversal.
- Composite-key encoding distinguishes UTF-8 component boundaries. Rejected
  session-store batches do not change stored records. Loaded and appended
  nested values are detached when they honor `copy.deepcopy`, as JSON-like
  data does; custom Python copy behavior remains the caller's responsibility.
- Manifest verification requires HMAC authentication by default. Missing,
  malformed or invalid authentication must fail before artifact paths are
  opened. Explicit checksum-only verification is unauthenticated.
- Artifact checks use a single no-follow, nonblocking regular-file descriptor,
  a size-derived read budget and observed metadata/path checks.
- Export writes a same-directory temporary file before replacement. Failures
  must preserve the prior destination; final destination symlinks must not be
  followed.
- Bubblewrap mount order is preserved. Cgroup inspection must distinguish
  unreadable/invalid records from unlimited limits and must not claim host
  enforcement from namespace-visible readings.

These are implementation properties to test, not a guarantee that an
application integrating the package is secure.

## Reporting and severity

Report a reachable break of one of these properties with the affected revision,
trusted and attacker-controlled inputs, expected and observed behavior, and a
small synthetic reproduction. Explain the application boundary and impact.
Incorrect status reporting or data corruption can matter even without a proven
cross-user security impact; label correctness and robustness issues accurately.

Do not publish sensitive reproductions, keys or private data in public issues.
GitHub private vulnerability reporting is enabled on
[the repository security page](https://github.com/oscarcsn/blue-security-engine/security).
Use **Report a vulnerability** there to send the report privately to the maintainer.

Triage, remediation and disclosure timing depend on the report and maintainer
availability. No response SLA, CVE assignment or automatic public credit is
promised.

## Research scope and limitations

Use local copies, authorized assets and bounded synthetic fixtures. This policy
does not authorize testing maintainer infrastructure or any third-party system.

A delimiter-safe key is not tenant authorization. Valid HMAC authenticates a
payload to holders of the shared key; it does not identify an individual signer
or prove the truth of telemetry. File checks do not freeze an artifact against
later writes, and atomic replacement does not provide crash durability.
Trusted parent directories are required.

Generated Bubblewrap arguments are configuration, not proof of confinement.
Visible cgroup completeness can include unlimited limits and omit hidden host
ancestors. Finite aggregate quotas, runtime isolation and cleanup require a
separately verified supervisor. See [DESIGN.md](docs/DESIGN.md).
