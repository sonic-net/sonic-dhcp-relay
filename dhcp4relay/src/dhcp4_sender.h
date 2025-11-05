#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#define BOOTP_MIN_LEN 300
/**
 * @code                            bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t len, const char* src_ip, bool use_src_ip);
 *
 * @brief                           send udp packet and return true if successful
 *
 * @param *buffer                   message buffer
 * @param sockaddr_in  target       target socket
 * @param len                         length of message
 * @param src_ip                    source IP address as string (optional)
 * @param use_src_ip                if true, use src_ip as source address
 *
 * @return boolean   True if packet successfully sent
 */
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t len, in_addr src_ip, bool use_src_ip);
