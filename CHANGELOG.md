# Changelog

Changes describe local development snapshots. A dated entry is not a published
release or an independently verified deployment.

## 0.1.0 — public repository and Linux CI verification, 2026-10-11 / 2026-10-12

- Rewrite the README around the implemented helpers, caller responsibilities
  and local installation and validation paths.
- Demonstrate post-signature artifact mutation detection (`HASH_MISMATCH` with
  a valid HMAC signature) in `bse.demo` and `bse-demo`.
- Add the `.github/ci` Linux Bubblewrap + `cgroup v2` admission and offline
  packaging verification harness tested on Ubuntu 22.04 (Python 3.10.12) and
  Ubuntu 24.04 (Python 3.12.3).
- Document manifest authentication, filesystem assumptions and the distinction
  between cgroup observations and external enforcement.
- Add contributing guidance, a reviewable security policy and synchronized
  validation records in `VALIDATION.md` and `VALIDATION.json`.

## 0.1.0 — local development snapshot, 2026-10-10

Historical receipt revision: `8b2a751b50ccac5fbc46b55e062a31315b42771d`.

- Iterative parent-linked graph validation and canonical composite-key encoding.
- Deep-copying in-memory session records with validation before mutation.
- HMAC-authenticated manifest verification required by default, explicit
  checksum-only mode, bounded regular-file hashing and atomic JSON export.
- Ordered Bubblewrap argument generation and visible cgroups v2 inspection.
- Packaged demo and Python typing marker.

The historical local receipt records 99 package test methods, 26 separate
integration methods, 66 separate supervisor methods and ten fixed arena cases.
See [README.md](README.md#validation-evidence) for scope and receipt identity;
see [VALIDATION.md](VALIDATION.md) for the current verification record.
