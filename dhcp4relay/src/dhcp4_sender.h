#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

/**
 * @code                            bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t n);
 *
 * @brief                           send udp packet and return true if successful
 *
 * @param *buffer                   message buffer
 * @param sockaddr_in target        target socket
 * @param n                         length of message
 * @param relay_config *config      pointer to relay_config
 * @param uint8_t msg_type          message type of dhcpv6 option of relayed message
 *
 * @return boolean   True if packet successfully sent
 */
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t n);
