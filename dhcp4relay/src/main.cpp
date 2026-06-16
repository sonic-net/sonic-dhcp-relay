#include <stdlib.h>
#include "logger.h"

#include <unordered_map>

#include "dhcp4relay.h"

bool dual_tor_sock = false;
char loopback[IF_NAMESIZE] = "Loopback0";

int main(int argc, char *argv[]) {
    swss::Logger::linkToDbNative("dhcp4relay");
    try {
        std::unordered_map<std::string, relay_config> interfaces;
        loop_relay(interfaces);
    } catch (std::exception &e) {
        SWSS_LOG_ERROR("An exception occurred.");
        return 1;
    }
    return 0;
}
