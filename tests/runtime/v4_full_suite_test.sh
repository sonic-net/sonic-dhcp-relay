#!/usr/bin/env bash
# The original v4 database mock reads ./test/database_config.json.
set -euo pipefail
cd "${TEST_SRCDIR}/${TEST_WORKSPACE}"
runner=$(realpath "$1")
fixture=$(realpath "$3")
export GTEST_FILTER="${2:-*}"
cd "$(dirname "$(dirname "$fixture")")"
exec "$runner" --gtest_output="xml:${XML_OUTPUT_FILE}"
