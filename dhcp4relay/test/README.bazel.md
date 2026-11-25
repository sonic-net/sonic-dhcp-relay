# Original DHCP4 source suite under Bazel

`//tests/runtime:v4_full_suite_test` builds all twelve translation units listed
by `test/subdir.mk` and executes all 62 original GTest cases (53 relay + 9
counter cases), with their original assertions. `//dhcp4relay:pcap_patch_test`
is independent and remains unchanged. This is unit/mock coverage, not real
network forwarding, installed-image acceptance, or a Redis integration suite.

The `relay_test` binary retains Make's `UNIT_TEST`, C++17 and AddressSanitizer
contract, but does not copy Make's unconditional `|| true`. Native compilation
uses the declared Debian toolchain. The local integration runner uses the
existing declared runtime archive closure and its loader (glibc 2.41), not the
Ubuntu host loader (2.39). It executes in a digest-pinned Debian container as
UID 65534, with readonly mounts/filesystem, no capabilities, no network and
no-new-privileges. Docker availability is required. No package is installed.

`socket_seam.cpp` is linked **only** into the test binary:

- AF_PACKET/SOCK_RAW/ETH_P_ALL is mapped to a real AF_UNIX datagram descriptor;
  the original socket and wildcard-bind arguments are asserted.
- Only PACKET_AUXDATA and PACKET_IGNORE_OUTGOING are adapted, asserting their
  production arguments. These options require the unavailable packet socket.
- All SOL_SOCKET calls, notably SO_ATTACH_FILTER, are real kernel calls. Both
  original valid-filter and invalid-filter assertions remain active.
- Original successful raw-descriptor fixtures are cleaned up after each case.

There is no production source change and no capability grant. The existing
UNIT_TEST branches (including mocked sender and VLAN socket handling), SWSS
mock translation units, and original case ordering remain in use. These are
inherited test semantics, not equivalent to exercising the production network
stack. Coverage instrumentation/report generation is not included in this
Bazel target; ASan is included.

## Leak-checking fixture corrections

The first full run passed all 62 cases but LeakSanitizer rejected 6068 bytes in
38 allocations. Unlike Make's `ASAN_OPTIONS=detect_leaks=0`, this target keeps
both ASan and LSan enabled. Two original mocked-ifaddrs allocations are released
with the existing helper after their final assertions, and one temporary
`relay_config` is deleted after copying it into the owning map. The seam drains
only messages still queued in the manager-only test pipe after a case completes,
disposing payloads by their original event type. It does not process a message,
change config/feature state, or skip assertions. Production files are untouched.

A Bazel-only include guard uses the declared external gmock-global header; the
original relative include remains active for Make (Make itself not rebuilt).

## Negative control

`//tests/runtime:v4_negative_control_test` is intentionally **manual and failing**.
It runs the original `DHCPRelayTest.bootp_pad_extends_short_packet` against a
separate test-only binary whose linker wrapper makes `bootp_pad` a no-op. Its
five original assertions must fail. The full-suite target always runs all cases;
no failure filter or skip is applied. This checks assertion effectiveness without
mutating production sources or the normal test binary.
