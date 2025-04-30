#include <iostream>
#include <signal.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <experimental/filesystem>
#include <chrono>
#include <thread>
#include <unistd.h>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "mock_relay.h"
#include <sys/syscall.h>

using namespace ::testing;
using namespace swss;

MOCK_GLOBAL_FUNC1(getifaddrs, int(struct ifaddrs **));
MOCK_GLOBAL_FUNC1(freeifaddrs, void(struct ifaddrs *));
MOCK_GLOBAL_FUNC3(write, ssize_t(int, const void*, size_t));

ssize_t RealWrite(int fd, const void *buf, size_t count) {
    return syscall(SYS_write, fd, buf, count);
}

struct ifaddrs *CreateMockIfaddrs(const std::string &vlan_ip, const std::string &vlan_mask, const std::string &vlan_name,
                                  const std::string &src_ip, const std::string &src_name) {
    struct ifaddrs *mock_ifaddrs = new ifaddrs;
    memset(mock_ifaddrs, 0, sizeof(ifaddrs));

    struct sockaddr_in *addr = new sockaddr_in;
    struct sockaddr_in *mask = new sockaddr_in;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(vlan_ip.c_str());
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = inet_addr(vlan_mask.c_str());

    mock_ifaddrs->ifa_addr = reinterpret_cast<struct sockaddr *>(addr);
    mock_ifaddrs->ifa_netmask = reinterpret_cast<struct sockaddr *>(mask);
    mock_ifaddrs->ifa_name = strdup(vlan_name.c_str());

    struct ifaddrs *mock_ifaddrs_src = new ifaddrs;
    memset(mock_ifaddrs_src, 0, sizeof(ifaddrs));

    struct sockaddr_in *src_addr = new sockaddr_in;
    src_addr->sin_family = AF_INET;
    src_addr->sin_addr.s_addr = inet_addr(src_ip.c_str());

    mock_ifaddrs_src->ifa_addr = reinterpret_cast<struct sockaddr *>(src_addr);
    mock_ifaddrs_src->ifa_name = strdup(src_name.c_str());

    mock_ifaddrs->ifa_next = mock_ifaddrs_src;
    return mock_ifaddrs;
}

void FreeMockIfaddrs(struct ifaddrs *mock_ifaddrs) {
    if (mock_ifaddrs) {
        delete reinterpret_cast<sockaddr_in *>(mock_ifaddrs->ifa_addr);
        delete reinterpret_cast<sockaddr_in *>(mock_ifaddrs->ifa_netmask);
        if (mock_ifaddrs->ifa_next) {
            delete reinterpret_cast<sockaddr_in *>(mock_ifaddrs->ifa_next->ifa_addr);
            free(mock_ifaddrs->ifa_next->ifa_name);
            delete mock_ifaddrs->ifa_next;
        }
        free(mock_ifaddrs->ifa_name);
        delete mock_ifaddrs;
    }
}

TEST(helper, to_string)
{
    EXPECT_EQ("0", to_string(0));
}

TEST(helper, string_to_mac_addr) {
    std::array<uint8_t, 6> mac_addr;
    ASSERT_TRUE(string_to_mac_addr("00:11:22:33:44:55", mac_addr));
    std::array<uint8_t, 6> expected = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    EXPECT_EQ(mac_addr, expected);
}

TEST(EncodeDecodeTLV, EncodeAndDecode) {
    uint8_t buffer[10] = {};
    uint8_t value[3] = {0x11, 0x22, 0x33};
    uint8_t length = 0;

    uint8_t encoded_length = encode_tlv(buffer, 1, 3, value);
    EXPECT_EQ(encoded_length, 5);
    EXPECT_EQ(buffer[0], 1);
    EXPECT_EQ(buffer[1], 3);
    EXPECT_EQ(buffer[2], 0x11);
    EXPECT_EQ(buffer[3], 0x22);
    EXPECT_EQ(buffer[4], 0x33);

    uint8_t *decoded_value = decode_tlv(buffer, 1, length, 5);
    ASSERT_NE(decoded_value, nullptr);
    EXPECT_EQ(length, 3);
    EXPECT_EQ(decoded_value[0], 0x11);
    EXPECT_EQ(decoded_value[1], 0x22);
    EXPECT_EQ(decoded_value[2], 0x33);
}

TEST(sock, sock_open)
{ 
  struct sock_filter ether_relay_filter[] = {
      { 0x6, 0, 0, 0x00040000 },
  };
  const struct sock_fprog ether_relay_fprog = {
      lengthof(ether_relay_filter),
      ether_relay_filter
  };
  EXPECT_GE(sock_open(&ether_relay_fprog), 0);
}

TEST(sock, sock_open_invalid_filter)
{
  const struct sock_fprog ether_relay_fprog = {0,{}};
  EXPECT_EQ(sock_open(&ether_relay_fprog), -1);
}

TEST(prepareConfig, prepare_relay_server_config) {
    struct relay_config config{};
    config.servers.push_back("192.168.1.1");
    config.servers.push_back("10.0.0.1");

    prepare_relay_server_config(config);

    ASSERT_EQ(config.servers_sock.size(), 2); 

    EXPECT_EQ(config.servers_sock[0].sin_family, AF_INET);
    EXPECT_EQ(config.servers_sock[0].sin_port, htons(67)); 
    EXPECT_EQ(config.servers_sock[0].sin_addr.s_addr, inet_addr("192.168.1.1"));

    EXPECT_EQ(config.servers_sock[1].sin_family, AF_INET);
    EXPECT_EQ(config.servers_sock[1].sin_port, htons(67));
    EXPECT_EQ(config.servers_sock[1].sin_addr.s_addr, inet_addr("10.0.0.1"));
}

TEST(prepareConfig, prepare_relay_interface_config) {
    struct ifaddrs *mock_ifaddrs = CreateMockIfaddrs("192.168.1.1", "255.255.255.0", "Vlan100", "192.168.1.2", "Ethernet4");
    struct relay_config interface_config{};
    interface_config.vlan = "Vlan100";
    interface_config.source_interface = "Ethernet4"; 

    EXPECT_GLOBAL_CALL(getifaddrs, getifaddrs(_)).WillOnce(DoAll(testing::SetArgPointee<0>(mock_ifaddrs), Return(0)));
    EXPECT_GLOBAL_CALL(freeifaddrs, freeifaddrs(_)).Times(1);

    prepare_relay_interface_config(interface_config);

    EXPECT_EQ(interface_config.link_address.sin_addr.s_addr, inet_addr("192.168.1.1"));
    EXPECT_EQ(interface_config.link_address_netmask.sin_addr.s_addr, inet_addr("255.255.255.0"));
    EXPECT_EQ(interface_config.src_intf_sel_addr.sin_addr.s_addr, inet_addr("192.168.1.2"));  // Now should pass!

    FreeMockIfaddrs(mock_ifaddrs);
}

TEST(prepareConfig, prepare_vlan_sockets)
{
  struct relay_config config{};
  config.link_address.sin_addr.s_addr = htonl(0x01010101);
  struct iphdr ip_hdr;
  std::string s_addr = "1.1.1.1";
  inet_pton(AF_INET, s_addr.c_str(), &ip_hdr.saddr);

  config.servers.push_back("3.3.3.3");
  config.servers.push_back("4.4.4.4");

  config.vlan = "Vlan200";
  EXPECT_EQ(prepare_vlan_sockets(config), 0);
  EXPECT_GE(config.client_sock, 0);
  EXPECT_GE(config.lo_sock, 0);
}

TEST(prepareConfig, prepare_vrf_sockets) {
    struct relay_config config{};
    config.vrf = "default";

    EXPECT_EQ(prepare_vrf_sockets(config), 0);
    EXPECT_GE(config.vrf_sock, 0);
    EXPECT_GE(vrf_sock_map["default"].sock, 0);
    EXPECT_EQ(vrf_sock_map["default"].ref_count, 1);
    vrf_sock_map.clear();
}

TEST(prepareConfig, update_vlan_mapping)
{
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    swss::Table vlan_member_table(config_db.get(), "VLAN_MEMBER");
    swss::Table vlan_interface_table(config_db.get(), "VLAN_INTERFACE");

    std::string key = "Vlan200|Ethernet8";
    std::vector<std::pair<std::string, std::string>> values = {
            {"tagging_mode", "untagged"},
    };

    std::string vlan_key = "Vlan200";
    std::vector<std::pair<std::string, std::string>> vlan_values = {
         {"vrf_name", "VrfRed"},
    };
        
    vlan_member_table.set(key, values);
    vlan_interface_table.set(vlan_key, vlan_values);
    
    // add case 
    update_vlan_mapping(vlan_key, true);
    
    EXPECT_EQ(vlan_map["Ethernet8"], vlan_key);
    EXPECT_EQ(vlan_vrf_map[vlan_key], "VrfRed");
    
    //delete case
    update_vlan_mapping(vlan_key, false);
    
    EXPECT_EQ(vlan_map.find("Ethernet8"), vlan_map.end());
    EXPECT_EQ(vlan_vrf_map.find(vlan_key), vlan_vrf_map.end());
}

TEST(relayConfig, handle_vlan_events) {
    event_config event;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1)) 
                     .WillRepeatedly(Invoke(RealWrite));
    std::unordered_map<std::string, relay_config> vlans;
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
    
    swss::Table vlan_member_table(config_db.get(), "VLAN_MEMBER");
    swss::Table vlan_interface_table(config_db.get(), "VLAN_INTERFACE");

    std::string key = "Vlan200|Ethernet8";
    std::vector<std::pair<std::string, std::string>> values = {
            {"tagging_mode", "untagged"},
    };

    std::string vlan_key = "Vlan200";
    std::vector<std::pair<std::string, std::string>> vlan_values = {
         {"vrf_name", "VrfRed"},
    };

    vlan_member_table.set(key, values);
    vlan_interface_table.set(vlan_key, vlan_values);
  
    struct ifaddrs *mock_ifaddrs = CreateMockIfaddrs("1.1.1.1", "255.255.255.0", "Vlan200", "2.2.2.2", "Ethernet8");

    EXPECT_GLOBAL_CALL(getifaddrs, getifaddrs(_)).WillOnce(DoAll(testing::SetArgPointee<0>(mock_ifaddrs), Return(0)));
    EXPECT_GLOBAL_CALL(freeifaddrs, freeifaddrs(_)).Times(1);
    relay_config *config = new relay_config();
    config->vlan = "Vlan200";
    config->is_add = true;
    config->config_db = config_db;
    config->state_db = state_db;
    config->source_interface = "Ethernet8";
    config->servers = {"192.168.1.1","10.0.0.1"};
    config->vrf = "default";
    event.type = DHCPv4_RELAY_CONFIG_UPDATE;
    event.msg = static_cast<void *>(config);
    
    int pipe_fds[2];
    ASSERT_NE(pipe(pipe_fds), -1);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    ASSERT_TRUE(vlans.find("Vlan200") != vlans.end());

    ASSERT_EQ(vlans["Vlan200"].servers_sock.size(), 2);

    EXPECT_EQ(vlans["Vlan200"].servers_sock[0].sin_family, AF_INET);
    EXPECT_EQ(vlans["Vlan200"].servers_sock[0].sin_port, htons(67));
    EXPECT_EQ(vlans["Vlan200"].servers_sock[0].sin_addr.s_addr, inet_addr("192.168.1.1"));

    EXPECT_EQ(vlans["Vlan200"].servers_sock[1].sin_family, AF_INET);
    EXPECT_EQ(vlans["Vlan200"].servers_sock[1].sin_port, htons(67));
    EXPECT_EQ(vlans["Vlan200"].servers_sock[1].sin_addr.s_addr, inet_addr("10.0.0.1"));

    EXPECT_EQ(vlans["Vlan200"].link_address.sin_addr.s_addr, inet_addr("1.1.1.1"));
    EXPECT_EQ(vlans["Vlan200"].link_address_netmask.sin_addr.s_addr, inet_addr("255.255.255.0"));
    EXPECT_EQ(vlans["Vlan200"].src_intf_sel_addr.sin_addr.s_addr, inet_addr("2.2.2.2"));
    
    EXPECT_GE(vlans["Vlan200"].vrf_sock, 0);
    EXPECT_GE(vrf_sock_map["default"].sock, 0);
    EXPECT_EQ(vrf_sock_map["default"].ref_count, 1);

    EXPECT_GE(vlans["Vlan200"].client_sock, 0);
    EXPECT_GE(vlans["Vlan200"].lo_sock, 0);

    /*Vlan deletion.*/
    relay_config *config_del = new relay_config();
    config_del->vlan = "Vlan200";
    config_del->is_add = false;
   
    vlans["Vlan200"].client_sock = -1; 
    vlans["Vlan200"].lo_sock = -1; 
    vlans["Vlan200"].vrf_sock = -1; 
    event.msg = static_cast<void *>(config_del);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);
    
    config_event_callback(pipe_fds[0], 0, &vlans);
    ASSERT_TRUE(vlans.find("Vlan200") == vlans.end());
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    FreeMockIfaddrs(mock_ifaddrs);
}

TEST(relayConfig, handle_interface_events) {
    int pipe_fds[2];
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Invoke(RealWrite));
    ASSERT_NE(pipe(pipe_fds), -1);
    relay_config *config = new relay_config();
    std::unordered_map<std::string, relay_config> vlans;
    config->vlan = "Vlan100";
    config->is_add = true;
    config->src_intf_sel_addr.sin_family = AF_INET;
    config->src_intf_sel_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    
    event_config event;
    event.type = DHCPv4_RELAY_INTERFACE_UPDATE;
    event.msg = static_cast<void *>(config);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    ASSERT_TRUE(vlans.find("Vlan100") != vlans.end());
    EXPECT_EQ(vlans["Vlan100"].src_intf_sel_addr.sin_family, AF_INET);
    EXPECT_EQ(vlans["Vlan100"].src_intf_sel_addr.sin_addr.s_addr, inet_addr("192.168.1.1"));
    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST(relayConfig, handle_metadata_events) {
    int pipe_fds[2];
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Invoke(RealWrite));
    ASSERT_NE(pipe(pipe_fds), -1);
    std::unordered_map<std::string, relay_config> vlans;
    relay_config vlan1, vlan2;

    vlan1.vlan = "Vlan100";
    vlan2.vlan = "Vlan200";

    vlans["Vlan100"] = vlan1;
    vlans["Vlan200"] = vlan2;

    relay_config *metadata = new relay_config();

    metadata->hostname = "newHost";
    uint8_t test_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::copy(std::begin(test_mac), std::end(test_mac), std::begin(metadata->host_mac_addr));
    
    event_config event;
    event.type = DHCPv4_RELAY_METADATA_UPDATE;
    event.msg = static_cast<void *>(metadata);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    for (const auto& vlan : vlans) {
        ASSERT_EQ(vlan.second.hostname, "newHost");

        ASSERT_TRUE(std::equal(std::begin(vlan.second.host_mac_addr), std::end(vlan.second.host_mac_addr),
                               std::begin(test_mac)));
    }
    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST(relay, signal_init) {
  signal_init();
  EXPECT_NE((uintptr_t)ev_sigint, NULL);
  EXPECT_NE((uintptr_t)ev_sigterm, NULL);
}

MOCK_GLOBAL_FUNC1(event_base_dispatch, int(struct event_base *));
MOCK_GLOBAL_FUNC2(event_add, int(struct event *, const struct timeval *));

TEST(relay, signal_start) {
  EXPECT_GLOBAL_CALL(event_add, event_add(_, NULL)).Times(5)
                    .WillOnce(Return(-1))
                    .WillOnce(Return(0)).WillOnce(Return(-1))
                    .WillOnce(Return(0)).WillOnce(Return(0));
  EXPECT_EQ(signal_start(), -1);
  EXPECT_EQ(signal_start(), -1);
  EXPECT_GLOBAL_CALL(event_base_dispatch, event_base_dispatch(_)).Times(1).WillOnce(Return(-1));
  EXPECT_EQ(signal_start(), 0);
}

TEST(DHCPMgrTest, initialize_config_listner) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(-1));
    dhcpMgr.initialize_config_listner();
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    
    swss::Table dhcp_table(config_db.get(), "DHCPV4_RELAY");
    swss::Table intf_table(config_db.get(), "INTERFACE");
    swss::Table loopback_intf_table(config_db.get(), "LOOPBACK_INTERFACE");
    swss::Table portchannel_intf_table(config_db.get(), "PORTCHANNEL_INTERFACE");
    swss::Table metadata_table(config_db.get(), "DEVICE_METADATA");

    std::string dhcp_key = "Vlan200";
    std::vector<std::pair<std::string, std::string>> dhcp_values = {
            {"dhcpv4_servers", "1.1.1.1,1.1.1.2"},
	    {"server_vrf", "VrfRed"},
            {"source_interface", "Ethernet4"},
	    {"agent_relay_mode", "discard"},
	    {"link_selection", "enable"},
	    {"server_id_override", "enable"},
	    {"vrf_selection", "enable"}
    };

    dhcp_table.set(dhcp_key, dhcp_values);

    std::string intf_key = "Ethernet4|192.168.1.1/24";
    std::vector<std::pair<std::string, std::string>> intf_values = {
            {"NULL", "NULL"},
    };

    intf_table.set(intf_key, intf_values);
    loopback_intf_table.set(intf_key, intf_values);
    portchannel_intf_table.set(intf_key, intf_values);

    std::string metadata_key = "localhost";
    std::vector<std::pair<std::string, std::string>> metadata_values = {
            {"hostname", "newHost"},
            {"mac", "00:11:22:33:44:55"}
    };

    metadata_table.set("host", metadata_values);
    metadata_table.set(metadata_key, metadata_values);

    std::this_thread::sleep_for(std::chrono::seconds(2));
}
