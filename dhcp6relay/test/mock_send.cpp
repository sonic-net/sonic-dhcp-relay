#include "mock_send.h"
#include <cstring>

uint8_t sender_buffer[65535];
int32_t valid_byte_count;
int last_used_sock;
sockaddr_in6 last_target;
int sendUdpCount;

bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in6 target, uint32_t n) {
    last_used_sock = sock;
    valid_byte_count = n;
    memcpy(sender_buffer, buffer, n);
    last_target = target;
    sendUdpCount++;
    return true;
}
