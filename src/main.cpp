#include <stdlib.h>
#include <syslog.h>
#include <unordered_map>
#include "configInterface.h"

bool dual_tor_sock = false;
char loopback[IF_NAMESIZE] = "Loopback0";

static void usage()
{
    printf("Usage: ./dhcp6relay [-u <loopback interface>]\n");
    printf("\tloopback interface: is the loopback interface for dual tor setup\n");
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        switch (argv[1][1])
        {
            case 'u':
                if (strlen(argv[i + 1]) < IF_NAMESIZE) {
                    std::memset(loopback, 0, IF_NAMESIZE);
                    std::memcpy(loopback, argv[i + 1], strlen(argv[i + 1]));
                } else {
                    syslog(LOG_ERR, "loopback interface name over length %d.\n", IF_NAMESIZE);
                    return 1;
                }
                dual_tor_sock = true;
                i += 2;
                break;
            default:
                fprintf(stderr, "%s: Unknown option\n", basename(argv[0]));
                usage();
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
