# Validation scope

[VALIDATION.json](VALIDATION.json) distinguishes the historical laboratory run from the publication candidate's current verification. Results identify their actual scope and environment. A local receipt hash is an integrity identifier, not an independent certification.

The package contains 99 test methods. The additional 26 integration and 66 supervisor methods belong to a separate laboratory harness. Its 10 fixed arena cases are also separate from the library suite. Historical results reference source revision 8b2a751 and are not re-labeled as a new execution.

The publication candidate passed 99 unit tests and an offline sdist-to-wheel build on October 11, 2026 UTC. The wheel was installed without network or runtime dependencies. Its typing marker and demo resource were checked, and both installed demo entry points exited successfully with HMAC verification. Build artifacts were not retained by that verification profile; their filenames and hashes are recorded in VALIDATION.json.

The candidate includes a regression for deep and circular HMAC payloads. These inputs reject authentication without reading an artifact. A controlled encoder RecursionError checks the structured INVALID_SIGNATURE result; the actual encoder depth threshold varies with the Python runtime. The first verification exposed an overly narrow expected status in this regression. That assertion was corrected before the passing run. Other existing tests cover malformed keys, input-copy isolation, graph cycles and identifiers, manifest authentication and bounded file handling, mount order, and conservative cgroup interpretation.

The code and build-input hashes in VALIDATION.json identify what was executed. This summary and its JSON record were generated after that run. Full supervisor records remain private because they include machine-specific operational metadata. Their hashes identify local records, rather than substituting for public reproduction. A separate delivery manifest identifies the final publication files.

The local verification environment is Linux, with a clean environment, private namespaces, no network, aggregate cgroup limits, bounded runtime and output, and checked cleanup. This runner is maintained separately from BSE. Verify its deployment before executing code; library installation alone does not create it.

For independent reproduction, run the package's unit suite and demo in an approved isolated environment as described in README. Offline packaging verification must also build the sdist, build a wheel from that sdist, install without dependencies or network, and run both installed demo entry points. Check that the typing marker and documented files are present.

The recorded tests are synthetic. They do not prove host-wide cgroup enforcement, arbitrary-runner safety, cross-tenant authorization, adoption, certifications, or acceptance into a vendor program. Before/after production-service samples matched; continuous availability was not measured. The local prepublication run above did not include remote CI. Subsequent public CI is recorded below.

## Verified public CI

[Run 38113465597](https://github.com/oscarcsn/blue-security-engine/actions/runs/38113465597) tested public commit `3f41a1f815c69d44305a03279d6026f1b505aca6` on Ubuntu 22.04 / Python 3.10.12 and Ubuntu 24.04 / Python 3.12.3. Both jobs passed all 99 package tests with zero skips and completed offline sdist-to-wheel construction, installation, typing-marker checks and both installed demos. Admission verified five aggregate cgroup controls, private namespaces, zero capabilities, a clean environment and network restrictions before package imports. Unit and staging cleanup passed.

The trusted CI provisioning step prepares pinned build dependencies and, when required, a targeted Bubblewrap user-namespace profile on the disposable VM. Package code and build backends run offline inside the admitted worker. This demonstrates the fixed profile on those two environments; it does not certify a production host or an arbitrary runner. The earlier local record remains unchanged in scope.
