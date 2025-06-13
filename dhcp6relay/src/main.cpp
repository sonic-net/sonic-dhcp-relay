#include <stdlib.h>
#include <syslog.h>
#include <unordered_map>
#include "config_interface.h"

bool dual_tor_sock = false;
char loopback[IF_NAMESIZE] = "Loopback0";

static void usage()
{
    printf("Usage: ./dhcp6relay [-u <loopback interface>]\n");
    printf("\tloopback interface: is the loopback interface for dual tor setup\n");
}

int main(int argc, char *argv[]) {
    if (argc > 2) {
        switch (argv[1][1])
        {
            case 'u':
                if (strlen(argv[2]) != 0 && strlen(argv[2]) < IF_NAMESIZE) {
                    std::memset(loopback, 0, IF_NAMESIZE);
                    std::memcpy(loopback, argv[2], strlen(argv[2]));
                } else {
                    syslog(LOG_ERR, "loopback interface name over length %d.\n", IF_NAMESIZE);
                    return 1;
                }
                dual_tor_sock = true;
                break;
            default:
                fprintf(stderr, "%s: Unknown option\n", basename(argv[0]));
                usage();
                return 0;
        }
    }
    try {
        std::unordered_map<std::string, relay_config> vlans;
        initialize_swss(vlans);
        loop_relay(vlans);
    }
    catch (std::exception &e)
    {
        syslog(LOG_ERR, "An exception occurred.\n");
        return 1;
    }
    return 0;
}
