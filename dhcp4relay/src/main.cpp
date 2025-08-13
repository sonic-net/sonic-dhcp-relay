#include <stdlib.h>
#include <syslog.h>

#include <unordered_map>

#include "dhcp4relay.h"

bool dual_tor_sock = false;
char loopback[IF_NAMESIZE] = "Loopback0";

int main(int argc, char *argv[]) {
    try {
        std::unordered_map<std::string, relay_config> vlans;
        loop_relay(vlans);
    } catch (std::exception &e) {
        syslog(LOG_ERR, "An exception occurred.\n");
        return 1;
    }
    return 0;
}
