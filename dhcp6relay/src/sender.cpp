#include "sender.h"
#include <syslog.h>
#include <errno.h>
#include <cstring>
#include <arpa/inet.h>

/**
 * @code                            bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in6 target, uint32_t n);
 *
 * @brief                           send udp packet and return true if successful
 *
 * @param *buffer                   message buffer
 * @param sockaddr_in6 target       target socket
 * @param n                         length of message
 * @param relay_config *config      pointer to relay_config
 * @param uint8_t msg_type          message type of dhcpv6 option of relayed message
 * 
 * @return boolean   True if packet successfully sent
 */
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in6 target, uint32_t n) {
    if(sendto(sock, buffer, n, 0, (const struct sockaddr *)&target, sizeof(target)) == -1) {
        char server_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(target.sin6_addr), server_addr, INET6_ADDRSTRLEN);
        syslog(LOG_ERR, "sendto: Failed to send to target address: %s, error: %s\n", server_addr, strerror(errno));
        return false;
    }
    return true;
}
