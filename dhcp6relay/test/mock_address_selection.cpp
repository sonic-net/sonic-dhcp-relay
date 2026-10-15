#include <array>
#include <map>
#include <unistd.h>
#include "mock_relay.h"

using namespace ::testing;

static ifaddrs *mock_interfaces = nullptr;
static std::map<int, sockaddr_in6> bound_addresses;

// Other tests use real calls; repeated enumeration returns the same snapshot.
extern "C" {
int __real_getifaddrs(struct ifaddrs **);
void __real_freeifaddrs(struct ifaddrs *);
int __real_bind(int, const struct sockaddr *, socklen_t);

int __wrap_getifaddrs(struct ifaddrs **addresses) {
    if (!mock_interfaces) {
        return __real_getifaddrs(addresses);
    }
    *addresses = mock_interfaces;
    return 0;
}

void __wrap_freeifaddrs(struct ifaddrs *addresses) {
    if (!mock_interfaces) {
        __real_freeifaddrs(addresses);
    }
}

int __wrap_bind(int sock, const struct sockaddr *address, socklen_t length) {
    if (!mock_interfaces) {
        return __real_bind(sock, address, length);
    }
    EXPECT_EQ(sizeof(sockaddr_in6), length);
    bound_addresses[sock] = *reinterpret_cast<const sockaddr_in6 *>(address);
    EXPECT_EQ(AF_INET6, bound_addresses[sock].sin6_family);
    EXPECT_EQ(htons(RELAY_PORT), bound_addresses[sock].sin6_port);
    return 0;
}
}

class VlanAddressSelection : public TestWithParam<std::string> {
protected:
    relay_config config{};
    std::array<ifaddrs, 4> interfaces{};
    std::array<sockaddr_in6, 4> addresses{};
    const char *ips[4] = {"2001:db8:1::1", "2001:db8:2::1", "fe80::1", "2001:db8:ffff::2"};
    const std::string keys[2] = {
        "VLAN_INTERFACE|Vlan4093|2001:db8:1::1/64",
        "VLAN_INTERFACE|Vlan4093|2001:0DB8:0002:0000:0000:0000:0000:0001/80"};
    std::vector<int> sockets;
    bool saved_dual_tor_sock = dual_tor_sock;
    int saved_send_count = sendUdpCount;

    void SetUp() override {
        dual_tor_sock = GetParam() == "DualToRSecondaryFirst";
        sendUdpCount = 0;
        config.interface = "Vlan4093";
        config.config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
        config.state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);
        config.servers = {"2001:db8:ffff::1"};
        config.is_interface_id = true;
        config.config_db->hset(keys[0], "secondary", "false");
        config.config_db->hset(keys[1], "secondary", "true");
        for (size_t i = 0; i < interfaces.size(); ++i) {
            addresses[i].sin6_family = AF_INET6;
            ASSERT_EQ(1, inet_pton(AF_INET6, ips[i], &addresses[i].sin6_addr));
            interfaces[i].ifa_name = const_cast<char *>(i == 3 ? "Loopback0" : "Vlan4093");
            interfaces[i].ifa_addr = reinterpret_cast<sockaddr *>(&addresses[i]);
            interfaces[i].ifa_next = i + 1 < interfaces.size() ? &interfaces[i + 1] : nullptr;
        }
        if (GetParam() != "PrimaryFirst") {
            std::swap(interfaces[0].ifa_addr, interfaces[1].ifa_addr);
        }
        addresses[2].sin6_scope_id = 93;
        mock_interfaces = interfaces.data();
    }

    void TearDown() override {
        mock_interfaces = nullptr;
        bound_addresses.clear();
        for (int sock : sockets) {
            close(sock);
        }
        for (const auto &key : keys) {
            config.config_db->del(key);
        }
        config.state_db->del("DHCPv6_COUNTER_TABLE|" + config.interface);
        addr_vlan_map.erase(ips[0]);
        addr_vlan_map.erase(ips[1]);
        dual_tor_sock = saved_dual_tor_sock;
        sendUdpCount = saved_send_count;
    }
};

TEST_P(VlanAddressSelection, primary_identity) {
    int gua_sock = -1, lla_sock = -1;
    ASSERT_EQ(0, prepare_vlan_sockets(gua_sock, lla_sock, config));
    sockets = {gua_sock, lla_sock};
    if (dual_tor_sock) {
        config.lo_sock = prepare_lo_socket("Loopback0");
        ASSERT_GE(config.lo_sock, 0);
        sockets.push_back(config.lo_sock);
        EXPECT_THAT(bound_addresses.at(config.lo_sock).sin6_addr.s6_addr,
                    ElementsAreArray(addresses[3].sin6_addr.s6_addr));
    }
    prepare_relay_config(config, gua_sock, 42);
    const auto &primary = addresses[0].sin6_addr.s6_addr;
    EXPECT_THAT(config.link_address.sin6_addr.s6_addr, ElementsAreArray(primary))
        << "link_address must use the primary VLAN IPv6 address";
    EXPECT_THAT(bound_addresses.at(gua_sock).sin6_addr.s6_addr, ElementsAreArray(primary))
        << "VLAN GUA socket must bind the primary IPv6 address";
    EXPECT_THAT(bound_addresses.at(lla_sock).sin6_addr.s6_addr, ElementsAreArray(addresses[2].sin6_addr.s6_addr));
    EXPECT_EQ(93u, bound_addresses.at(lla_sock).sin6_scope_id);
    EXPECT_THAT(addr_vlan_map, Contains(Pair(std::string(ips[0]), config.interface)))
        << "primary VLAN address must be registered";
    EXPECT_EQ(0u, addr_vlan_map.count(ips[1])) << "secondary address must not replace primary VLAN identity";

    uint8_t msg[] = {DHCPv6_MESSAGE_TYPE_SOLICIT, 0, 0, 1};
    ip6_hdr ip_hdr{};
    ether_header ether_hdr{};
    ASSERT_EQ(1, inet_pton(AF_INET6, "fe80::2", &ip_hdr.ip6_src));
    relay_client(msg, sizeof(msg), &ip_hdr, &ether_hdr, &config);
    EXPECT_EQ(1, sendUdpCount);
    EXPECT_EQ(dual_tor_sock ? config.lo_sock : gua_sock, last_used_sock);
    RelayMsg relay;
    ASSERT_TRUE(relay.UnmarshalBinary(sender_buffer, valid_byte_count));
    EXPECT_THAT(relay.m_msg_hdr.link_address.s6_addr, ElementsAreArray(primary))
        << "Relay-Forward link_address must use the primary VLAN IPv6 address";
    EXPECT_THAT(relay.m_option_list.Get(OPTION_INTERFACE_ID), ElementsAreArray(primary))
        << "InterfaceID must use the primary VLAN IPv6 address";
}

INSTANTIATE_TEST_SUITE_P(address_order, VlanAddressSelection,
    Values("PrimaryFirst", "SecondaryFirst", "DualToRSecondaryFirst"),
    [](const TestParamInfo<std::string> &info) { return info.param; });
