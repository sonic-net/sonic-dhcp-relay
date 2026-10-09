#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#define BOOTP_MIN_LEN 300

/**
 * Copy and zero-pad a short packet to BOOTP_MIN_LEN, updating its length.
 * Does nothing when padding is disabled or unnecessary.
 */
void bootp_pad(uint8_t *out, const uint8_t *buffer, uint32_t *len, bool pad);

/**
 * Send a UDP packet to the target address.
 *
 * @param sock        socket descriptor
 * @param buffer      message buffer
 * @param target      target address
 * @param len         message length
 * @param src_ip      optional source IPv4 address
 * @param use_src_ip  use src_ip as the source address when true
 * @param pad         pad short BOOTP packets when true
 * @return true when the packet is sent successfully
 */
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t len, in_addr src_ip, bool use_src_ip, bool pad);
