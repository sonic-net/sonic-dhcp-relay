#include "dhcp4_sender.h"

#include <arpa/inet.h>
#include <errno.h>
#include "logger.h"

#include <cstring>

void bootp_pad(uint8_t *out, const uint8_t *buffer, uint32_t *len, bool pad) {
   if (pad && *len < BOOTP_MIN_LEN) {
      memcpy(out, buffer, *len);
      memset(out + *len, 0, BOOTP_MIN_LEN - *len);
      *len = BOOTP_MIN_LEN;
   }
}

#ifndef UNIT_TEST
bool send_udp(int sock, uint8_t *buffer, struct sockaddr_in target, uint32_t len, in_addr src_ip, bool use_src_ip, bool pad) {
   uint8_t padded[BOOTP_MIN_LEN];
   uint32_t orig_len = len;
   bootp_pad(padded, buffer, &len, pad);
   if (len != orig_len)
      buffer = padded;

   if (use_src_ip && src_ip.s_addr != 0) {
        // Enable IP_PKTINFO on the socket
        int on = 1;
        setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));

        struct msghdr msg = {};
        struct iovec iov = {};
        char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];

        iov.iov_base = buffer;
        iov.iov_len = len;

        msg.msg_name = &target;
        msg.msg_namelen = sizeof(target);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
        memset(pktinfo, 0, sizeof(struct in_pktinfo));
        pktinfo->ipi_spec_dst = src_ip;

        msg.msg_controllen = cmsg->cmsg_len;

        if (sendmsg(sock, &msg, 0) == -1) {
            char server_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(target.sin_addr), server_addr, INET_ADDRSTRLEN);
            SWSS_LOG_ERROR("sendmsg: Failed to send to target address: %s, error: %s", server_addr, strerror(errno));
            return false;
        }
    } else {
        if (sendto(sock, buffer, len, 0, (const struct sockaddr *)&target, sizeof(target)) == -1) {
            char server_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(target.sin_addr), server_addr, INET_ADDRSTRLEN);
            SWSS_LOG_ERROR("sendto: Failed to send to target address: %s, error: %s", server_addr, strerror(errno));
            return false;
        }
    }
    return true;
}
#endif
