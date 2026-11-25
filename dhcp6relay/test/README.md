The Bazel DHCPv6 tests start a private Redis process with `run_tests.py`. The fixture waits for its UNIX socket, supplies an isolated SONiC database configuration to the test binary through `DHCP6RELAY_TEST_DATABASE_CONFIG`, and cleans up the process and files after the suite.

To run the fixture tests locally, install Python 3 and Redis, then run the following from the repository root.

```sh
python3 -m unittest discover -s dhcp6relay/test -p run_tests_test.py -v
```
