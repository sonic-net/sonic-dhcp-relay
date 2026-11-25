#!/usr/bin/env bash
set -euo pipefail

tool_dir="${RUNNER_TEMP:?}/relay-tools"
mkdir -p "$tool_dir"
curl --fail --location --retry 3 https://releases.bazel.build/8.5.1/release/bazel-8.5.1-linux-x86_64 -o "$tool_dir/bazel"
echo "61d89402f0368e64b6c827be5de79d8e65382e8124c3cbb97325611a1851392e  $tool_dir/bazel" | sha256sum --check
chmod 755 "$tool_dir/bazel"
echo "$tool_dir" >> "${GITHUB_PATH:?}"
