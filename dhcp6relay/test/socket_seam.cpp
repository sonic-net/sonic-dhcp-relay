// Test-only link seam: use real unprivileged datagram sockets for packet setup.
// Production binaries never link this file. Kernel filter validation, receive
// buffer configuration and nonblocking/reuse setup remain real syscalls.
#include <cerrno>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <set>
#include <unistd.h>
#include "gtest/gtest.h"
#include <event2/event.h>
#include <stdexcept>

namespace {
std::set<int> packet_fds;
std::set<int> udp_fds;
std::set<event *> allocated_events;
}
extern "C" event *__real_event_new(event_base *, evutil_socket_t, short, event_callback_fn, void *);
extern "C" void __real_event_free(event *);
extern "C" event *__wrap_event_new(event_base *base, evutil_socket_t fd, short flags,
                                    event_callback_fn callback, void *arg) {
    event *value = __real_event_new(base, fd, flags, callback, arg);
    if (value) allocated_events.insert(value);
    return value;
}
extern "C" void __wrap_event_free(event *value) {
    allocated_events.erase(value);
    __real_event_free(value);
}
extern "C" int __real_socket(int, int, int);
extern "C" int __real_bind(int, const struct sockaddr *, socklen_t);
extern "C" int __real_close(int);
extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (domain != AF_PACKET) {
        const int fd = __real_socket(domain, type, protocol);
        if (fd >= 0 && domain == AF_INET6 && type == SOCK_DGRAM && protocol == 0)
            udp_fds.insert(fd);
        return fd;
    }
    EXPECT_EQ(type, SOCK_RAW);
    EXPECT_EQ(protocol, htons(ETH_P_ALL));
    const int fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd >= 0) packet_fds.insert(fd);
    return fd;
}
extern "C" int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (udp_fds.count(fd)) {
        // Check the production DHCP endpoint, then ask the real kernel to bind
        // an ephemeral port. Unit tests need neither CAP_NET_BIND_SERVICE nor
        // exclusive ownership of the host's DHCP port; address errors stay real.
        EXPECT_NE(addr, nullptr);
        EXPECT_EQ(len, sizeof(sockaddr_in6));
        if (!addr || len != sizeof(sockaddr_in6)) return -1;
        auto endpoint = *reinterpret_cast<const sockaddr_in6 *>(addr);
        EXPECT_EQ(endpoint.sin6_family, AF_INET6);
        EXPECT_EQ(endpoint.sin6_port, htons(547));
        endpoint.sin6_port = 0;
        return __real_bind(fd, reinterpret_cast<const sockaddr *>(&endpoint), len);
    }
    if (!packet_fds.count(fd)) return __real_bind(fd, addr, len);
    EXPECT_EQ(len, sizeof(sockaddr_ll));
    const auto *packet = reinterpret_cast<const sockaddr_ll *>(addr);
    EXPECT_EQ(packet->sll_family, AF_PACKET);
    EXPECT_EQ(packet->sll_protocol, htons(ETH_P_ALL));
    EXPECT_EQ(packet->sll_ifindex, 0);
    // There is no physical interface in this unit fixture. The packet bind
    // arguments are asserted above, not silently redirected to a host device.
    return 0;
}
extern "C" int __wrap_close(int fd) {
    packet_fds.erase(fd);
    udp_fds.erase(fd);
    return __real_close(fd);
}
// sock_open's legacy test does not close its successful fd; loop_relay throws
// intentionally at its unconfigured event_add mock. Clean fixture descriptors.
class PacketSocketCleanup : public testing::EmptyTestEventListener {
    void OnTestEnd(const testing::TestInfo &) override {
        for (int fd : packet_fds) __real_close(fd);
        packet_fds.clear();
    }
    void OnTestProgramEnd(const testing::UnitTest &) override {
        for (int fd : udp_fds) __real_close(fd);
        udp_fds.clear();
        // Legacy signal tests share globals across cases; do not free these at
        // each case boundary. Release only events not freed by shutdown_relay,
        // including the event abandoned by loop_relay's expected exception.
        for (event *value : allocated_events) __real_event_free(value);
        allocated_events.clear();
    }
};
static const bool registered = [] {
    testing::UnitTest::GetInstance()->listeners().Append(new PacketSocketCleanup);
    return true;
}();
