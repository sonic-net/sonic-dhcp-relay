#include <stdlib.h>
#include <syslog.h>
#include "configInterface.h"

int main(int argc, char *argv[]) {
    try {
        std::vector<relay_config> vlans;
        swss::DBConnector state_db("STATE_DB", 0);
        swss::RedisClient m_stateDbRedisClient(&state_db);
        initialize_swss(&vlans);
        loop_relay(&vlans, &m_stateDbRedisClient);
    }
    catch (std::exception &e)
    {
        syslog(LOG_ERR, "An exception occurred.\n");
        return 1;
    }
    return 0;
}
