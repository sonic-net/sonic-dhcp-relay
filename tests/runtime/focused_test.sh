#!/usr/bin/env bash
set -euo pipefail
cd "${TEST_SRCDIR}/${TEST_WORKSPACE}"
exec "$1" --gtest_output="xml:${XML_OUTPUT_FILE}"
