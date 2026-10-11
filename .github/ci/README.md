# Fixed offline CI profile

This configuration validates BSE's own 99-test suite, then builds an sdist,
builds a wheel from that sdist, installs it without an index, and checks the
installed typing resource and both demo entry points. It uses the system
Python on GitHub-hosted Ubuntu 22.04 (3.10) and Ubuntu 24.04 (3.12). A passing
job demonstrates only that version/platform and the checks actually run.

The ephemeral runner prepares Bubblewrap from Ubuntu repositories and three
version- and SHA-256-pinned PyPI wheels before admission. Package code and the
build backend execute only after the gate, without network access. No API,
model, GPU, production service, or repository secret is used. Checkout does
not retain its credentials, and workflow permissions are `contents: read`.

The root-owned sealed source, policy, runtime and dependencies are read-only
inside Bubblewrap. All namespaces are private, capabilities are zero, the
environment is cleared, and host homes, SSH configuration and administrative
sockets are absent. The entire worker process tree shares one cgroup with
768 MiB memory, zero swap, 25% CPU, 48 tasks and a 240-second runtime limit.
Private scratch is a 64 MiB tmpfs with 2,048 inodes. The external controller
also bounds output and time, checks the own-unit identity before admission,
and cleans only that unit and its unique staging directory.

This is a closed profile whose scripts and workflow are trusted configuration,
not a general executor or protection against an operator changing that policy.
It requires cgroup v2, systemd, functional unprivileged user namespaces and
Bubblewrap/AppArmor support on the selected runner. It fails before target
imports when a required control is unavailable; there is no host-execution
fallback. Do not run it on the productive `hp` workstation. CI does not certify
production deployment, enforce an application's tenant authorization, or
prove compatibility with Python versions absent from successful job results.
