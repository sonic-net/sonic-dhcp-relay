#!/usr/bin/env bash
# Source-only AMD64 gate. Requires Linux AMD64 and verified Bazel 8.5.1.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${BAZEL:?set BAZEL to the verified Bazel 8.5.1 executable}"
: "${CI_SOURCE_SHA:?set CI_SOURCE_SHA to the checked-out commit}"
: "${CI_STATE:?set CI_STATE to a new private absolute directory}"
: "${CI_EVIDENCE:?set CI_EVIDENCE to a new absolute receipt directory}"
[[ "$CI_STATE" = /* && "$CI_EVIDENCE" = /* ]]
case "$(realpath -m "$CI_STATE")/" in
  "$(realpath -m "$CI_EVIDENCE")/"*) echo 'CI_STATE must be outside uploaded evidence'; exit 1 ;;
esac
mkdir -p "$CI_EVIDENCE"
exec > >(tee "$CI_EVIDENCE/driver.log") 2>&1
finish() {
  rc=$?
  trap - EXIT
  printf '%s\n' "$rc" > "$CI_EVIDENCE/exit-code.txt"
  if [[ -f MODULE.bazel.lock ]]; then cp MODULE.bazel.lock "$CI_EVIDENCE/"; fi
  # Copy only known outputs, never a cache, environment dump or credential file.
  if [[ -d bazel-testlogs/tests/runtime ]]; then
    find -L bazel-testlogs/tests/runtime -type f \( -name test.xml -o -name test.log \) -exec cp --parents '{}' "$CI_EVIDENCE/" \;
  fi
  (cd "$CI_EVIDENCE" && find . -type f ! -name SHA256SUMS ! -name driver.log -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  exit "$rc"
}
trap finish EXIT
[[ $(git rev-parse HEAD) == "$CI_SOURCE_SHA" ]] || { echo 'Wrong source checkout'; exit 1; }
[[ $(uname -sm) == 'Linux x86_64' ]]
[[ $(cat .bazelversion) == 8.5.1 ]]
[[ $("$BAZEL" --version) == 'bazel 8.5.1' ]]
# A dirty checkout could conceal which sources the receipt actually covers.
[[ -z $(git status --porcelain --untracked-files=no) ]]
[[ ! -e "$CI_STATE" ]] || { echo 'CI_STATE must be new (no reused outputs)'; exit 1; }
mkdir -p "$CI_STATE"/{tmp,repos,output,sandbox}
export TMPDIR="$CI_STATE/tmp" MAKEFLAGS=-j1 CMAKE_BUILD_PARALLEL_LEVEL=1 NINJAFLAGS=-j1
{
  git rev-parse HEAD HEAD^{tree}
  sha256sum "$BAZEL" .bazelrc MODULE.bazel
  python3 --version
  uname -sm
} > "$CI_EVIDENCE/provenance.txt"
cat > "$CI_STATE/ci.bazelrc" <<EOF
common --repository_cache=$CI_STATE/repos
common --host_platform=@sonic_build_infra//platforms:x86_64_trixie
common --platforms=@sonic_build_infra//platforms:x86_64_trixie
build --jobs=2
build --local_resources=cpu=2
build --local_resources=memory=8192
build --sandbox_base=$CI_STATE/sandbox
build --action_env=TMPDIR=$CI_STATE/tmp
build --action_env=MAKEFLAGS=-j1
build --action_env=CMAKE_BUILD_PARALLEL_LEVEL=1
build --action_env=NINJAFLAGS=-j1
EOF
cat > "$CI_STATE/bazel" <<EOF
#!/usr/bin/env bash
exec "$BAZEL" --batch --host_jvm_args=-Xmx2048m --output_user_root="$CI_STATE/output" --nosystem_rc --nohome_rc --bazelrc="$CI_STATE/ci.bazelrc" "\$@"
EOF
chmod 755 "$CI_STATE/bazel"
bazel="$CI_STATE/bazel"
cp "$CI_STATE/ci.bazelrc" "$CI_EVIDENCE/"
python3 -m unittest discover -s tools/bazel -p '*_test.py' -v
"$bazel" mod graph --lockfile_mode=update > "$CI_EVIDENCE/module-graph.txt"
artifacts=(//dhcp4relay:runtime //dhcp4relay:runtime.debug_symbols //dhcp6relay:runtime //dhcp6relay:runtime.debug_symbols //:dhcp4_metadata //:dhcp6_metadata)
tests=(//tests/runtime:sender_test //tests/runtime:pcap_patch_test //tests/runtime:v4_full_suite_test //tests/runtime:v6_full_suite_test)
selection="set(${artifacts[*]} ${tests[*]})"
"$bazel" cquery "$selection" --output=files > "$CI_EVIDENCE/configured-files.txt"
# Raw action graphs and BEPs may record command lines and process environment.
# Keep them in private job state; upload the gates' typed receipts instead.
"$bazel" aquery "deps($selection)" --output=jsonproto > "$CI_STATE/configured-actions.json"
python3 tools/bazel/ci_checks.py actions "$CI_STATE/configured-actions.json" --receipt "$CI_EVIDENCE/action-audit.json"
"$bazel" build "${artifacts[@]}" --build_event_json_file="$CI_STATE/build.bep.json"
mkdir -p "$CI_EVIDENCE/artifacts"
for target in "${artifacts[@]}"; do
  name="${target//\//_}"; name="${name//:/_}"
  mkdir -p "$CI_EVIDENCE/artifacts/$name"
  "$bazel" cquery "$target" --output=files > "$CI_EVIDENCE/artifacts/$name/outputs.txt"
  test -s "$CI_EVIDENCE/artifacts/$name/outputs.txt"
  while IFS= read -r output; do
    test -f "$output"
    cp "$output" "$CI_EVIDENCE/artifacts/$name/"
  done < "$CI_EVIDENCE/artifacts/$name/outputs.txt"
done
"$bazel" test "${tests[@]}" --nocache_test_results --test_output=all --build_event_json_file="$CI_STATE/test.bep.json"
python3 tools/bazel/ci_checks.py tests bazel-testlogs --receipt "$CI_EVIDENCE/test-audit.json"
# Production dependency inputs are immutable; generated resolution is evidence.
git diff --exit-code
