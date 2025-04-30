#include "dhcp4_sender.h"

#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>

#include <cstring>

/**
 * @code                            bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t n);
 *
 * @brief                           send udp packet and return true if successful
 *
 * @param *buffer                   message buffer
 * @param sockaddr_in  target       target socket
 * @param n                         length of message
 * @param relay_config *config      pointer to relay_config
 * @param uint8_t msg_type          message type of dhcpv6 option of relayed message
 *
 * @return boolean   True if packet successfully sent
 */
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t n) {
    if (sendto(sock, buffer, n, 0, (const struct sockaddr *)&target, sizeof(target)) == -1) {
        char server_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(target.sin_addr), server_addr, INET_ADDRSTRLEN);
        syslog(LOG_ERR, "sendto: Failed to send to target address: %s, error: %s\n", server_addr, strerror(errno));
        return false;
    }
    return true;
}
