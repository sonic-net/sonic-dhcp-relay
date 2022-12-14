#include <stdlib.h>
#include <syslog.h>
#include <unordered_map>
#include "configInterface.h"

bool dual_tor_sock = false;

static void usage()
{
    printf("Usage: ./dhcp6relay {-d}\n");
    printf("\t-d: enable dual tor option\n");
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        switch (argv[1][1])
        {
            case 'd':
                dual_tor_sock = true;
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
