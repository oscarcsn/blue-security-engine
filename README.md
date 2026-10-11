# Blue Security Engine

Blue Security Engine (BSE) is a Python standard-library package for validating
parent-linked session graphs, encoding composite keys, and checking artifact
integrity with HMAC authentication. It also generates Bubblewrap arguments and
inspects visible cgroups v2 resource limits.

The package is maintained by Oscar Cisneros with AI assistance. The current
development version is `0.1.0`, under the [MIT license](LICENSE). Public release
and CI results have not been established for this checkout.

## Components

| Module | Provides |
|---|---|
| `bse.defense.cycle_detector` | Iterative cycle detection and validation of node identifiers and duplicates |
| `bse.defense.safe_store` | UTF-8 length-prefixed keys and in-memory storage with deep copies of validated records |
| `bse.forensics.manifest` | SHA-256 artifact records, HMAC payload authentication and atomic JSON export |
| `bse.isolation.bubblewrap` | Bubblewrap arguments preserving caller-specified mount order |
| `bse.isolation.cgroups` | Controller readings and conservative effective limits within the visible hierarchy |

BSE supplies individual controls; the application supplies authorization,
trusted directories, input budgets and execution policy. The Bubblewrap builder
does not launch a sandbox, and the cgroup inspector does not enforce quotas.
See [design and trust boundaries](docs/DESIGN.md).

## Local use

Runtime imports require Python 3.9+ and no third-party Python packages.
Manifest filesystem controls and isolation helpers target Linux. Distribution
builds require `setuptools>=61.0` and `wheel`; Bubblewrap and an execution
supervisor are separate operating-system dependencies.

Use a local checkout through `PYTHONPATH=src`. For an installed wheel, the
equivalent imports and the `bse-demo` command are available. No published
package index or clone URL is assumed here.

To install a locally built wheel, mount it in an isolated scratch environment
with a writable disposable Python environment. Adapt the artifact path to the
actual offline build output:

```bash
python3 -m pip install --no-index --no-deps /artifacts/blue_security_engine-0.1.0-py3-none-any.whl
python3 -B -m bse.demo
```

Run the following source-checkout commands **inside an approved isolated environment**, with
source mounted read-only and a writable synthetic scratch directory:

```bash
PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONPATH=src python3 -B -m bse.demo
```

In the development laboratory, execution uses its external Bubblewrap harness
and supervisor. That harness is not shipped in this package. The supervisor
must verify namespaces, aggregate descendant quotas, a clean environment,
credential exclusion and cleanup before admitting work. Library installation
alone does not establish these controls.

The demo uses synthetic data and checks generated Bubblewrap arguments. It
does not execute the generated configuration or demonstrate runtime confinement.

## Example: separate key components before storing records

```python
from bse import LengthPrefixedKeySerializer, validate_acyclic_entries

key_a = LengthPrefixedKeySerializer.serialize("tenant/acme", "run")
key_b = LengthPrefixedKeySerializer.serialize("tenant", "acme", "run")
assert key_a != key_b
assert LengthPrefixedKeySerializer.deserialize(key_a) == ("tenant/acme", "run", None)

validate_acyclic_entries([
    {"uuid": "scan"},
    {"uuid": "review", "parentUuid": "scan"},
])
```

The encoding prevents delimiter ambiguity. Authorize the caller's tenant and
session before selecting a key; encoding is not an access-control decision.
The graph validator checks the supplied records before traversal, rather than
intercepting an application's later traversals.

For authenticated artifact verification, use a caller-held HMAC key and check
the complete report. [The manifest example](docs/DESIGN.md#artifact-manifests)
explains the distinction between payload authentication and artifact validity.

## Validation evidence

The historical local receipt dated October 10, 2026 references package revision
`8b2a751b50ccac5fbc46b55e062a31315b42771d` and records:

| Scope | Distinct test methods | Part of this package's suite? |
|---|---:|---|
| Package | 99 | Yes |
| Separate laboratory integration suite | 26 | No |
| Separate laboratory supervisor suite | 66 | No |

It also records ten fixed arena cases and an offline build passing. The total
of 191 methods combines three scopes; it is not the package unit-test count.
The local receipt is `BSE-FINISH-20261010-FINAL-VERIFICATION.json`, SHA-256
`57fcedd80f686d16332b918fa09159407f824782b2bfa800b704258961be17f4`.

These are historical results, not a new run or CI status. A checksum identifies
a receipt; public reproducibility also needs the matching source and inputs.
The current publication candidate passed 99 package tests and offline
sdist-to-wheel build, installation and both demo entry points in the isolated
local verification profile. [VALIDATION.md](VALIDATION.md) and
[VALIDATION.json](VALIDATION.json) identify the tested code hashes, environment,
scope and limits. Remote CI has not been run.

## Contributing and security reports

Read [CONTRIBUTING.md](CONTRIBUTING.md) for bounded synthetic checks and
[SECURITY.md](SECURITY.md) for security properties and reporting.
GitHub private vulnerability reporting is usable only after it has been
enabled on the actual published repository.

Changes are recorded in [CHANGELOG.md](CHANGELOG.md).
