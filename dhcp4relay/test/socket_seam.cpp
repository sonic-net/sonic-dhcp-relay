// Test-only adapter for the raw packet descriptor. Production links neither
// this file nor --wrap. Real kernel BPF attach/reject validation is retained.
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <set>
#include "gtest/gtest.h"
#include "../src/dhcp4relay.h"
#include <fcntl.h>

namespace {
std::set<int> packet_fds;
std::set<int> udp_fds;
}
extern "C" int __real_socket(int, int, int);
extern "C" int __real_bind(int, const sockaddr *, socklen_t);
extern "C" int __real_close(int);
extern "C" int __real_setsockopt(int, int, int, const void *, socklen_t);
extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (domain != AF_PACKET) {
        const int fd = __real_socket(domain, type, protocol);
        if (fd >= 0 && domain == AF_INET && type == SOCK_DGRAM && protocol == 0)
            udp_fds.insert(fd);
        return fd;
    }
    EXPECT_EQ(type, SOCK_RAW);
    EXPECT_EQ(protocol, htons(ETH_P_ALL));
    int fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd >= 0) packet_fds.insert(fd);
    return fd;
}
extern "C" int __wrap_bind(int fd, const sockaddr *addr, socklen_t len) {
    if (udp_fds.count(fd)) {
        // Check the production DHCP endpoint, then ask the real kernel to bind
        // an ephemeral port. Unit tests need neither CAP_NET_BIND_SERVICE nor
        // exclusive ownership of the host's DHCP port; address errors stay real.
        EXPECT_NE(addr, nullptr);
        EXPECT_EQ(len, sizeof(sockaddr_in));
        if (!addr || len != sizeof(sockaddr_in)) return -1;
        auto endpoint = *reinterpret_cast<const sockaddr_in *>(addr);
        EXPECT_EQ(endpoint.sin_family, AF_INET);
        EXPECT_EQ(endpoint.sin_port, htons(67));
        endpoint.sin_port = 0;
        return __real_bind(fd, reinterpret_cast<const sockaddr *>(&endpoint), len);
    }
    if (!packet_fds.count(fd)) return __real_bind(fd, addr, len);
    EXPECT_EQ(len, sizeof(sockaddr_ll));
    if (len != sizeof(sockaddr_ll)) return -1;
    const auto *packet = reinterpret_cast<const sockaddr_ll *>(addr);
    EXPECT_EQ(packet->sll_family, AF_PACKET);
    EXPECT_EQ(packet->sll_protocol, htons(ETH_P_ALL));
    EXPECT_EQ(packet->sll_ifindex, 0);
    return 0;
}
extern "C" int __wrap_setsockopt(int fd, int level, int opt, const void *value, socklen_t len) {
    // These packet-only flags cannot be set on the substitute AF_UNIX socket.
    // Assert the exact production contract; no blanket setsockopt success seam.
    if (packet_fds.count(fd) && level == SOL_PACKET &&
        (opt == PACKET_AUXDATA || opt == PACKET_IGNORE_OUTGOING)) {
        EXPECT_EQ(len, sizeof(int));
        EXPECT_NE(value, nullptr);
        if (len != sizeof(int) || !value) return -1;
        EXPECT_EQ(*static_cast<const int *>(value), 1);
        return 0;
    }
    return __real_setsockopt(fd, level, opt, value, len);
}
extern "C" int __wrap_close(int fd) {
    packet_fds.erase(fd);
    udp_fds.erase(fd);
    return __real_close(fd);
}
class PacketSocketCleanup : public testing::EmptyTestEventListener {
    void OnTestEnd(const testing::TestInfo &) override {
        // Manager-only cases enqueue heap-owned messages without running the
        // relay consumer. Drain/dispose after all assertions, before the next
        // InitConfigPipeForTest closes that queue. No feature behavior is mocked.
        if (config_pipe[0] > STDERR_FILENO) {
            int flags = fcntl(config_pipe[0], F_GETFL);
            if (flags >= 0) {
                fcntl(config_pipe[0], F_SETFL, flags | O_NONBLOCK);
                event_config message;
                while (read(config_pipe[0], &message, sizeof(message)) == sizeof(message)) {
                    switch (message.type) {
                    case DHCPv4_RELAY_CONFIG_UPDATE:
                    case DHCPv4_RELAY_INTERFACE_UPDATE:
                    case DHCPv4_SERVER_RELAY_CONFIG_UPDATE:
                    case DHCPv4_RELAY_DUAL_TOR_UPDATE:
                        delete static_cast<relay_config *>(message.msg); break;
                    case DHCPv4_RELAY_VLAN_MEMBER_UPDATE:
                        delete static_cast<vlan_member_config *>(message.msg); break;
                    case DHCPv4_RELAY_PORTCHANNEL_MEMBER_UPDATE:
                        delete static_cast<portchannel_member_config *>(message.msg); break;
                    case DHCPv4_RELAY_VLAN_INTERFACE_UPDATE:
                        delete static_cast<vlan_interface_config *>(message.msg); break;
                    case DHCPv4_RELAY_PORT_UPDATE:
                        delete static_cast<port_config *>(message.msg); break;
                    // Scalar notification events carry no owned payload; the
                    // legacy producer does not initialize their msg member.
                    default: break;
                    }
                }
                fcntl(config_pipe[0], F_SETFL, flags);
            }
        }
        for (int fd : packet_fds) __real_close(fd);
        packet_fds.clear();
    }
    void OnTestProgramEnd(const testing::UnitTest &) override {
        // Some upstream cases intentionally keep successful fixture sockets.
        for (int fd : udp_fds) __real_close(fd);
        udp_fds.clear();
    }
};
static const bool registered = [] {
    testing::UnitTest::GetInstance()->listeners().Append(new PacketSocketCleanup);
    return true;
}();
