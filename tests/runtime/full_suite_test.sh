#!/usr/bin/env bash
# Run the original v6 fixture and all gtests through declared runtime launchers.
set -euo pipefail
cd "${TEST_SRCDIR}/${TEST_WORKSPACE}"
exec "$1" --redis-server "$(realpath "$2")" -- "$(realpath "$3")" --gtest_output="xml:${XML_OUTPUT_FILE}"
