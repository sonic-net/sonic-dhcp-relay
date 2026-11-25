# Bazel DHCP relay source build

Bazel builds both DHCP relay daemons from source and exports runtime TARs,
matching debug symbols, and package metadata. Existing Make/package entry points
and gitlinks are retained. These Bazel targets do not generate DEBs.

## Dependencies

Use Bazel 8.5.1 and the SONiC registry/BCR endpoints in `.bazelrc`. The module
consumes the published native `pcapplusplus@24.9.0.sonic.1` library. Its v24.09
source archive and SONiC random-source-port patch are byte-identical to the Make
inputs in `dhcp4relay`; downstream consumers need no private CMake build or
m4/bison/flex override. The existing patch remains in its Make-owned directory.

The declared Infra `.39-81476192...` and Distroless `.21` consume the single
shared production APT lock. The `dhcpmon_debian`, `dhcp_relay_test_debian`, and
`trixie` collections supply target libraries and test runtime dependencies.
There are no relay-local APT lockfiles or facts-mode resolver comparisons.
Normal builds validate and read the shared lock without refreshing packages.

Common remains `.9-334389...`, with source-built libnl and libyang runtime
outputs. The header-only gmock-global test input is fixed to the existing gitlink
`6552faa2a94250ed0192dbd62e608d37fafcc216`; GitHub source archives do not contain
submodule contents, so Bazel fetches that exact checksummed archive.

## Build and test

Select both the execution and target platforms explicitly. The supported gate
is Linux AMD64 with the Debian Trixie toolchain; ARM64 and live DHCP forwarding
are separate validation scopes.

```sh
bazel mod graph --lockfile_mode=update
bazel build --host_platform=@sonic_build_infra//platforms:x86_64_trixie \
  //dhcp4relay:runtime //dhcp4relay:runtime.debug_symbols \
  //dhcp6relay:runtime //dhcp6relay:runtime.debug_symbols \
  //:dhcp4_metadata //:dhcp6_metadata
bazel test --host_platform=@sonic_build_infra//platforms:x86_64_trixie \
  --nocache_test_results --test_output=all \
  //tests/runtime:sender_test //tests/runtime:pcap_patch_test \
  //tests/runtime:v4_full_suite_test //tests/runtime:v6_full_suite_test
```

Install the CI report parser with `python3 -m pip install --require-hashes -r tools/bazel/requirements-ci.txt` before running the validation script.

The four runtime gates execute the existing C++ test binaries and all original
assertions: 3 sender tests, 2 PcapPlusPlus regression tests, 62 DHCP4 tests, and
47 DHCP6 tests. They use Infra's declared native runtime launcher, which checks
ELF architecture and transitive `DT_NEEDED` providers before invoking the target
loader. Docker, privileged containers, and host target libraries are unnecessary.
The test-only socket seams preserve real kernel BPF checks while avoiding raw
socket privileges. They assert the requested DHCP UDP ports (67/547), then
perform real binds to ephemeral ports so non-root tests need no privileged
ports; the address, socket options and bind errors remain real. The manual `:v4_negative_control_test` must fail the original
`bootp_pad` assertions and is excluded from normal passing test selections.

DHCP6 retains the source-owned `test/run_tests.py` fixture and launches a locked
Redis executable through the shared ELF tool rule. Redis has a private temporary
UNIX socket, no TCP listener or persistence, and is stopped on success/failure.
The fixture and associated source changes originated in Guohan Lu's
[PR #1](https://github.com/securely1g/sonic-dhcp-relay/pull/1); their attribution is
preserved in the source history.

## Source CI

`.github/workflows/bazel.yml` runs on every PR and checks the actual head.
`tools/bazel/ci.sh` audits the configured transitive actions for DEB producers
before building the six artifact targets above. It executes all four gates
without test-result caching, rejects skipped/disabled/missing test coverage,
and uploads the six outputs, typed action/test audit receipts, module resolution,
and build/JUnit logs through an explicit artifact allowlist. Raw action graphs
and build/test BEPs remain in private `CI_STATE`, outside the uploaded evidence;
they can contain command lines and environment values.
CodeQL and Semgrep keep their existing independent workflows.

For the same gate locally, set `BAZEL` to a verified 8.5.1 binary,
`CI_SOURCE_SHA` to `git rev-parse HEAD`, and `CI_STATE`/`CI_EVIDENCE` to new
absolute directories, then run `bash tools/bazel/ci.sh`. Build/test execution is
bounded to two jobs and an 8 GiB scheduling budget. `MODULE.bazel.lock` is ignored
generated evidence; the shared APT production lock remains authoritative.
