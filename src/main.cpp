#include <stdlib.h>
#include <syslog.h>
#include "configInterface.h"
#include <iostream>

int main(int argc, char *argv[]) {
    try {
        /*
        unsigned char udp[] = { 
            0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 0x01, 0x00, 
            0x30, 0x39 };
        char *ptr = (char *)udp;
        static uint8_t buffer[4096];
        auto current_buffer_position = buffer;

        const uint8_t *current_position = (uint8_t *)ptr;
        const uint8_t *tmp = NULL;

        auto udp_header = parse_udp(current_position, &tmp);
        current_position = tmp;
        auto dhcp_message_length = ntohs(udp_header->len) - sizeof(udphdr);
        relay_forward(current_buffer_position, parse_dhcpv6_hdr(current_position), dhcp_message_length);
        */
        //printf( "   |-Destination Address : %s \n", dst );
        //printf( "   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", ether_header->ether_shost[0] , ether_header->ether_shost[1] , ether_header->ether_shost[2] , ether_header->ether_shost[3] , ether_header->ether_shost[4] , ether_header->ether_shost[5] );
        //printf( "   |-Protocol            : %s \n",dst);
        std::vector<relay_config> vlans;
        swss::DBConnector state_db("STATE_DB", 0);
        initialize_swss(&vlans);
        loop_relay(&vlans, &state_db);
    }
    catch (std::exception &e)
    {
        syslog(LOG_ERR, "An exception occurred.\n");
        return 1;
    }
    return 0;
}