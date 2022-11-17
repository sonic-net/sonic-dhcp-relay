#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include "../src/sender.h"

extern uint8_t sender_buffer[4096];
extern int32_t valid_byte_count;
extern int last_used_sock;
extern sockaddr_in6 last_target;
extern int sendUdpCount;
