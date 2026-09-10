#include <array>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include "mock_relay.h"

using namespace ::testing;

MOCK_GLOBAL_FUNC1(mock_getifaddrs, int(struct ifaddrs **));
MOCK_GLOBAL_FUNC1(mock_freeifaddrs, void(struct ifaddrs *));
MOCK_GLOBAL_FUNC3(mock_bind, int(int, const struct sockaddr *, socklen_t));
MOCK_GLOBAL_FUNC1(mock_sleep, unsigned int(unsigned int));

static bool mock_addresses = false;

// Wrap only this test executable's calls; other tests retain their real sockets.
extern "C" {
int __real_getifaddrs(struct ifaddrs **);
void __real_freeifaddrs(struct ifaddrs *);
int __real_bind(int, const struct sockaddr *, socklen_t);
unsigned int __real_sleep(unsigned int);

int __wrap_getifaddrs(struct ifaddrs **addresses) {
    return mock_addresses ? mock_getifaddrs(addresses) : __real_getifaddrs(addresses);
}

void __wrap_freeifaddrs(struct ifaddrs *addresses) {
    if (mock_addresses) {
        mock_freeifaddrs(addresses);
    } else {
        __real_freeifaddrs(addresses);
    }
}

int __wrap_bind(int sock, const struct sockaddr *address, socklen_t length) {
    return mock_addresses ? mock_bind(sock, address, length) : __real_bind(sock, address, length);
}

unsigned int __wrap_sleep(unsigned int seconds) {
    return mock_addresses ? mock_sleep(seconds) : __real_sleep(seconds);
}
}

class VlanAddressSelection : public TestWithParam<bool> {
protected:
    relay_config config{};
    std::array<ifaddrs, 8> interfaces{};
    std::array<sockaddr_in6, 8> addresses{};
    size_t address_count = 0;
    std::vector<std::string> config_keys;
    std::vector<int> sockets;
    std::map<int, sockaddr_in6> bound_addresses;
    int gua_sock = -1;
    int lla_sock = -1;
    bool saved_dual_tor_sock;
    int saved_send_count;
    const char *primary = "2001:db8:1::1";
    const char *secondary = "2001:db8:2::1";
    const char *link_local = "fe80::1";
    const char *transport = "2001:db8:ffff::2";

    void SetUp() override {
        saved_dual_tor_sock = dual_tor_sock;
        saved_send_count = sendUdpCount;
        dual_tor_sock = false;
        sendUdpCount = 0;
        config.interface = "Vlan4093";
        config.config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
        config.state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);
        config.servers = {"2001:db8:ffff::1"};
        config.is_interface_id = true;
        mock_addresses = true;
    }

    void TearDown() override {
        mock_addresses = false;
        for (int sock : sockets) {
            close(sock);
        }
        for (const auto &key : config_keys) {
            config.config_db->del(key);
        }
        config.state_db->del("DHCPv6_COUNTER_TABLE|" + config.interface);
        for (auto itr = addr_vlan_map.begin(); itr != addr_vlan_map.end();) {
            if (itr->second == config.interface) {
                itr = addr_vlan_map.erase(itr);
            } else {
                ++itr;
            }
        }
        dual_tor_sock = saved_dual_tor_sock;
        sendUdpCount = saved_send_count;
    }

    void add_address(const char *name, const char *address) {
        ASSERT_LT(address_count, interfaces.size());
        auto &ifa = interfaces[address_count];
        auto &in6 = addresses[address_count];
        in6.sin6_family = AF_INET6;
        ASSERT_EQ(1, inet_pton(AF_INET6, address, &in6.sin6_addr));
        if (IN6_IS_ADDR_LINKLOCAL(&in6.sin6_addr)) {
            in6.sin6_scope_id = 93;
        }
        ifa.ifa_name = const_cast<char *>(name);
        ifa.ifa_addr = reinterpret_cast<sockaddr *>(&in6);
        if (address_count) {
            interfaces[address_count - 1].ifa_next = &ifa;
        }
        ++address_count;
    }

    void set_metadata(const std::string &prefix, const std::string &field, const std::string &value) {
        std::string key = "VLAN_INTERFACE|" + config.interface + "|" + prefix;
        config_keys.push_back(key);
        config.config_db->hset(key, field, value);
    }

    void add_primary_and_secondary(bool primary_first) {
        set_metadata("2001:db8:1::1/64", "secondary", "false");
        set_metadata("2001:0DB8:0002:0000:0000:0000:0000:0001/80", "secondary", "true");
        add_address("Vlan4094", "2001:db8:99::1");
        add_address("Vlan4093", primary_first ? primary : secondary);
        add_address("Vlan4093", primary_first ? secondary : primary);
        add_address("Vlan4093", link_local);
        add_address("Loopback0", transport);
        add_address("Ethernet0", "2001:db8:100::1");
    }

public:
    int record_bind(int sock, const sockaddr *address, socklen_t length) {
        EXPECT_EQ(sizeof(sockaddr_in6), length);
        auto in6 = reinterpret_cast<const sockaddr_in6 *>(address);
        EXPECT_EQ(AF_INET6, in6->sin6_family);
        EXPECT_EQ(htons(RELAY_PORT), in6->sin6_port);
        bound_addresses[sock] = *in6;
        return 0;
    }

protected:
    int prepare_sockets() {
        int result = prepare_vlan_sockets(gua_sock, lla_sock, config);
        if (result == 0) {
            sockets.push_back(gua_sock);
            sockets.push_back(lla_sock);
        }
        return result;
    }

    void expect_address(const char *expected, const in6_addr &actual) {
        in6_addr address{};
        ASSERT_EQ(1, inet_pton(AF_INET6, expected, &address));
        EXPECT_EQ(0, memcmp(&address, &actual, sizeof(address)));
    }

    void expect_vlan_identity(const char *expected) {
        prepare_relay_config(config, gua_sock, 42);
        expect_address(expected, config.link_address.sin6_addr);
        ASSERT_EQ(1, bound_addresses.count(gua_sock));
        expect_address(expected, bound_addresses.at(gua_sock).sin6_addr);
        ASSERT_EQ(1, bound_addresses.count(lla_sock));
        expect_address(link_local, bound_addresses.at(lla_sock).sin6_addr);
        EXPECT_EQ(93, bound_addresses.at(lla_sock).sin6_scope_id);
        ASSERT_EQ(1, addr_vlan_map.count(expected));
        EXPECT_EQ(config.interface, addr_vlan_map.at(expected));

        uint8_t msg[] = {DHCPv6_MESSAGE_TYPE_SOLICIT, 0, 0, 1};
        ip6_hdr ip_hdr{};
        ether_header ether_hdr{};
        ASSERT_EQ(1, inet_pton(AF_INET6, "fe80::2", &ip_hdr.ip6_src));
        relay_client(msg, sizeof(msg), &ip_hdr, &ether_hdr, &config);
        EXPECT_EQ(1, sendUdpCount);
        EXPECT_EQ(dual_tor_sock ? config.lo_sock : gua_sock, last_used_sock);
        RelayMsg relay;
        ASSERT_TRUE(relay.UnmarshalBinary(sender_buffer, valid_byte_count));
        expect_address(expected, relay.m_msg_hdr.link_address);
        auto interface_id = relay.m_option_list.Get(OPTION_INTERFACE_ID);
        ASSERT_EQ(sizeof(in6_addr), interface_id.size());
        EXPECT_EQ(0, memcmp(interface_id.data(), &config.link_address.sin6_addr, sizeof(in6_addr)));
    }
};

TEST_P(VlanAddressSelection, primary_identity) {
    add_primary_and_secondary(GetParam());
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_))
        .WillOnce(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(1);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(2)
        .WillRepeatedly(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(_)).Times(0);

    ASSERT_EQ(0, prepare_sockets());
    expect_vlan_identity(primary);
    EXPECT_EQ(0, addr_vlan_map.count(secondary));
}

TEST_P(VlanAddressSelection, dualtor_loopback_transport) {
    add_primary_and_secondary(GetParam());
    dual_tor_sock = true;
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(2)
        .WillRepeatedly(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(2);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(3)
        .WillRepeatedly(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(_)).Times(0);

    config.lo_sock = prepare_lo_socket("Loopback0");
    ASSERT_GE(config.lo_sock, 0);
    sockets.push_back(config.lo_sock);
    ASSERT_EQ(0, prepare_sockets());
    expect_vlan_identity(primary);
    expect_address(transport, bound_addresses.at(config.lo_sock).sin6_addr);
}

INSTANTIATE_TEST_SUITE_P(address_order, VlanAddressSelection, Values(false, true));

TEST_F(VlanAddressSelection, missing_metadata_is_primary) {
    for (bool missing_key : {false, true}) {
        SCOPED_TRACE(missing_key);
        if (!missing_key) {
            set_metadata("2001:db8:1::1/64", "NULL", "NULL");
        } else {
            config.config_db->del("VLAN_INTERFACE|Vlan4093|2001:db8:1::1/64");
        }
        address_count = 0;
        interfaces = {};
        add_address("Vlan4093", primary);
        add_address("Vlan4093", link_local);
        EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_))
            .WillOnce(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
        EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(1);
        EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(2)
            .WillRepeatedly(Invoke(this, &VlanAddressSelection::record_bind));
        EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(_)).Times(0);

        ASSERT_EQ(0, prepare_sockets());
        config.servers_sock.clear();
        sendUdpCount = 0;
        expect_vlan_identity(primary);
    }
}

TEST_F(VlanAddressSelection, first_primary_is_reused) {
    add_address("Vlan4093", primary);
    add_address("Vlan4093", secondary);
    add_address("Vlan4093", link_local);
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_))
        .WillOnce(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(1);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(2)
        .WillRepeatedly(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(_)).Times(0);

    ASSERT_EQ(0, prepare_sockets());
    expect_vlan_identity(primary);
}

TEST_F(VlanAddressSelection, missing_primary_retries_and_fails) {
    for (bool secondary_only : {false, true}) {
        SCOPED_TRACE(secondary_only);
        address_count = 0;
        interfaces = {};
        add_address("Vlan4094", primary);
        add_address("Vlan4093", link_local);
        if (secondary_only) {
            set_metadata("2001:db8:2::1/80", "secondary", "true");
            add_address("Vlan4093", secondary);
        }
        EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(6)
            .WillRepeatedly(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
        EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(6);
        EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(0);
        EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(5)).Times(6).WillRepeatedly(Return(0));

        EXPECT_EQ(-1, prepare_sockets());
        EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&config.link_address.sin6_addr));
        EXPECT_EQ(-1, fcntl(gua_sock, F_GETFD));
        EXPECT_EQ(-1, fcntl(lla_sock, F_GETFD));
    }
}

TEST_F(VlanAddressSelection, retry_refreshes_primary_address_and_metadata) {
    set_metadata("2001:db8:1::1/64", "secondary", "false");
    set_metadata("2001:db8:2::1/80", "secondary", "true");
    add_address("Vlan4093", primary);
    add_address("Vlan4093", secondary);
    add_address("Vlan4093", link_local);
    interfaces[0].ifa_next = nullptr;
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(2)
        .WillOnce(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)))
        .WillOnce(Invoke([this](ifaddrs **result) {
            set_metadata("2001:db8:1::1/64", "secondary", "true");
            set_metadata("2001:db8:2::1/80", "secondary", "false");
            interfaces[0].ifa_next = &interfaces[1];
            *result = interfaces.data();
            return 0;
        }));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(2);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(2)
        .WillRepeatedly(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(5)).Times(1).WillOnce(Return(0));

    ASSERT_EQ(0, prepare_sockets());
    expect_vlan_identity(secondary);
    EXPECT_EQ(0, addr_vlan_map.count(primary));
}

TEST_F(VlanAddressSelection, retry_does_not_reuse_disappeared_link_local) {
    add_address("Vlan4093", link_local);
    add_address("Vlan4093", primary);
    interfaces[0].ifa_next = nullptr;
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(6)
        .WillOnce(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)))
        .WillRepeatedly(DoAll(SetArgPointee<0>(&interfaces[1]), Return(0)));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(_)).Times(6);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(1)
        .WillOnce(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(5)).Times(6).WillRepeatedly(Return(0));

    EXPECT_EQ(-1, prepare_sockets());
    EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&config.link_address.sin6_addr));
    EXPECT_EQ(-1, fcntl(gua_sock, F_GETFD));
    EXPECT_EQ(-1, fcntl(lla_sock, F_GETFD));
}

TEST_F(VlanAddressSelection, missing_link_local_retries_and_fails) {
    add_address("Vlan4093", primary);
    add_address("Vlan4094", link_local);
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(6)
        .WillRepeatedly(DoAll(SetArgPointee<0>(interfaces.data()), Return(0)));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(interfaces.data())).Times(6);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(1)
        .WillOnce(Invoke(this, &VlanAddressSelection::record_bind));
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(5)).Times(6).WillRepeatedly(Return(0));

    EXPECT_EQ(-1, prepare_sockets());
    EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&config.link_address.sin6_addr));
    EXPECT_EQ(-1, fcntl(gua_sock, F_GETFD));
    EXPECT_EQ(-1, fcntl(lla_sock, F_GETFD));
}

TEST_F(VlanAddressSelection, getifaddrs_failure_retries) {
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(6).WillRepeatedly(Return(-1));
    EXPECT_GLOBAL_CALL(mock_freeifaddrs, mock_freeifaddrs(_)).Times(0);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(0);
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(5)).Times(6).WillRepeatedly(Return(0));

    EXPECT_EQ(-1, prepare_sockets());
    EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&config.link_address.sin6_addr));
    EXPECT_EQ(-1, fcntl(gua_sock, F_GETFD));
    EXPECT_EQ(-1, fcntl(lla_sock, F_GETFD));
}

TEST_F(VlanAddressSelection, missing_config_db_fails) {
    config.config_db.reset();
    EXPECT_GLOBAL_CALL(mock_getifaddrs, mock_getifaddrs(_)).Times(0);
    EXPECT_GLOBAL_CALL(mock_bind, mock_bind(_, _, _)).Times(0);
    EXPECT_GLOBAL_CALL(mock_sleep, mock_sleep(_)).Times(0);

    EXPECT_EQ(-1, prepare_sockets());
    EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&config.link_address.sin6_addr));
    EXPECT_EQ(-1, gua_sock);
    EXPECT_EQ(-1, lla_sock);
}

TEST_F(VlanAddressSelection, missing_selected_address_fails) {
    EXPECT_EXIT(prepare_relay_config(config, -1, 42), ExitedWithCode(EXIT_FAILURE), "");
    EXPECT_EQ(0, addr_vlan_map.count("::"));
}
