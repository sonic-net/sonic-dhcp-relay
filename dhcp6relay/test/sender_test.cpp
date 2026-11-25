#include "dhcp6relay/src/sender.h"
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <vector>

namespace {
int calls, socket_seen, flags_seen;
socklen_t address_size;
sockaddr_in6 address_seen;
std::vector<uint8_t> bytes_seen;
ssize_t send_result;
class SenderTest : public ::testing::Test {
protected:
    sockaddr_in6 destination{};
    void SetUp() override {
        calls = 0;
        bytes_seen.clear();
        destination.sin6_family = AF_INET6;
        destination.sin6_port = htons(547);
        destination.sin6_scope_id = 17;
        ASSERT_EQ(1, inet_pton(AF_INET6, "2001:db8::1", &destination.sin6_addr));
    }
};
}
extern "C" ssize_t __wrap_sendto(int sock, const void *buf, size_t size, int flags,
                                  const sockaddr *address, socklen_t address_len) {
    ++calls;
    socket_seen = sock;
    flags_seen = flags;
    address_size = address_len;
    std::memcpy(&address_seen, address, sizeof(address_seen));
    const auto *data = static_cast<const uint8_t *>(buf);
    bytes_seen.assign(data, data + size);
    if (send_result == -1) errno = ENETUNREACH;
    return send_result;
}
TEST_F(SenderTest, PreservesPacketAndScopedDestination) {
    uint8_t packet[] = {12, 0, 0xff, 0, 1, 0x80};
    send_result = sizeof(packet);
    EXPECT_TRUE(send_udp(42, packet, destination, sizeof(packet)));
    EXPECT_EQ(1, calls);
    EXPECT_EQ(42, socket_seen);
    EXPECT_EQ(0, flags_seen);
    EXPECT_EQ(sizeof(destination), address_size);
    EXPECT_EQ(0, std::memcmp(&destination, &address_seen, sizeof(destination)));
    EXPECT_EQ(std::vector<uint8_t>(packet, packet + sizeof(packet)), bytes_seen);
}
TEST_F(SenderTest, ReturnsFailureOnUnreachableNetwork) {
    uint8_t packet[] = {1, 0, 0, 1};
    send_result = -1;
    EXPECT_FALSE(send_udp(42, packet, destination, sizeof(packet)));
    EXPECT_EQ(1, calls);
}
TEST_F(SenderTest, PreservesEmptyDatagramBehavior) {
    uint8_t packet[] = {0};
    send_result = 0;
    EXPECT_TRUE(send_udp(42, packet, destination, 0));
    EXPECT_TRUE(bytes_seen.empty());
    EXPECT_EQ(1, calls);
}
