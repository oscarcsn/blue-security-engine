# Contributing

Start with the [design](docs/DESIGN.md) and [security policy](SECURITY.md).
Keep changes focused on a concrete behavior and preserve public API contracts
unless the incompatibility is documented.

## Development environment

BSE runtime code uses Python 3.9+ and the standard library. Building a wheel or
source distribution also requires setuptools and wheel. Linux filesystem
features, Bubblewrap and cgroups v2 are needed for the corresponding controls.

Run code and tests only in an authorized isolated runtime with a clean
environment, source mounted read-only, synthetic writable scratch space,
no production credentials and externally enforced finite resource limits.
The development laboratory's supervisor is external to this package; do not
infer isolation from importing BSE or generating a Bubblewrap command.

Inside that environment, the package checks are:

```bash
PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONPATH=src python3 -B -m bse.demo
```

Use an offline build with prepared dependencies when packaging is part of the
change. Test the resulting wheel and source distribution in separate scratch
environments. Do not install development artifacts into a production runtime.

## Change and validation expectations

- Add a small regression case for a changed boundary or failure mode, including
  a meaningful positive or negative control. Prefer deterministic synthetic
  fixtures and bounded inputs.
- Distinguish configuration checks, fixture checks and observed runtime
  behavior. A mock does not establish kernel enforcement or successful cleanup.
- Record the exact revision or source hashes, Python/Linux environment,
  command, isolation profile, outcome and artifact digests in the validation
  summary. Do not include keys, credentials or private operational evidence.
- Keep package, separate integration, supervisor and arena counts distinct.
  Update [CHANGELOG.md](CHANGELOG.md) and relevant API documentation.
- Run `git diff --check` and review the final patch. Submit it for local review;
  use a pull request after the destination repository is actually available.

The maintainer completes the current [VALIDATION.md](VALIDATION.md) and
[VALIDATION.json](VALIDATION.json) record after isolated verification. Historical
results do not prove a changed checkout or a future CI run.

## Publication checklist

Confirm the public repository, license, chosen revision, distribution
contents, reproducible package checks and private security-reporting channel.
Only link a release, package index or CI badge after verifying it exists.
Keep external laboratory evidence explicitly separate unless its reproducible
inputs and harness are also included.

See [SECURITY.md](SECURITY.md) before sharing a potential vulnerability.
