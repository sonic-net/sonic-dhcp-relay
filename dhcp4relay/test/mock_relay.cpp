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

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/PayloadLayer.h>

using namespace ::testing;
using namespace swss;

MOCK_GLOBAL_FUNC1(getifaddrs, int(struct ifaddrs **));
MOCK_GLOBAL_FUNC1(freeifaddrs, void(struct ifaddrs *));
MOCK_GLOBAL_FUNC3(write, ssize_t(int, const void*, size_t));
MOCK_GLOBAL_FUNC6(send_udp, bool(int, uint8_t *, struct sockaddr_in, uint32_t, in_addr, bool));

void encode_relay_option(pcpp::DhcpLayer *dhcp_pkt, relay_config *config);
void to_client(pcpp::DhcpLayer* dhcp_pkt, std::unordered_map<std::string, relay_config > *vlans,
                std::string src_ip);
void from_client(pcpp::DhcpLayer *dhcp_pkt, relay_config &config);

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

TEST(sock, sock_open) {
  struct sock_filter ether_relay_filter[] = {
      { 0x6, 0, 0, 0x00040000 },
  };
  const struct sock_fprog ether_relay_fprog = {
      lengthof(ether_relay_filter),
      ether_relay_filter
  };
  EXPECT_GE(sock_open(&ether_relay_fprog), 0);
}

TEST(sock, sock_open_invalid_filter) {
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
    EXPECT_EQ(interface_config.src_intf_sel_addr.sin_addr.s_addr, inet_addr("192.168.1.2"));

    FreeMockIfaddrs(mock_ifaddrs);
}

TEST(prepareConfig, prepare_vlan_sockets) {
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

TEST(prepareConfig, update_vlan_mapping) {
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

    /*Vlan deletion.*/
    relay_config *config_del = new relay_config();
    config_del->vlan = "Vlan200";
    config_del->is_add = false;
   
    vlans["Vlan200"].client_sock = -1; 
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

    event.type = DHCPv4_SERVER_IP_UPDATE;
    global_dhcp_server_ip = "192.168.1.1";
    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);
    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_EQ(vlans["Vlan100"].servers_sock[0].sin_family, AF_INET);
    EXPECT_EQ(vlans["Vlan100"].servers_sock[0].sin_port, htons(67));
    EXPECT_EQ(vlans["Vlan100"].servers_sock[0].sin_addr.s_addr, inet_addr("192.168.1.1"));

    event.type = DHCPv4_SERVER_FEATURE_UPDATE;
    event.msg = NULL;
    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);
    config_event_callback(pipe_fds[0], 0, &vlans);

    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST(relayConfig, handle_vlan_member_events) {
    int pipe_fds[2];
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Invoke(RealWrite));
    ASSERT_NE(pipe(pipe_fds), -1);

    std::unordered_map<std::string, relay_config> vlans;
    vlans["Vlan100"].vlan = "Vlan100";
    vlans["Vlan100"].client_sock = -1;
    vlans["Vlan100"].is_add = true;

    vlan_member_config *vlan_config = new vlan_member_config();

    vlan_config->is_add = true;
    vlan_config->interface = "Ethernet12";
    vlan_config->vlan = "Vlan100";

    event_config event;
    event.type = DHCPv4_RELAY_VLAN_MEMBER_UPDATE;
    event.msg = static_cast<void *>(vlan_config);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_EQ(vlan_map["Ethernet12"], "Vlan100");
    EXPECT_GE(vlans["Vlan100"].client_sock, 0);

    vlan_member_config *vlan_config_del = new vlan_member_config();

    vlans["Vlan100"].client_sock = -1;
    vlan_config_del->is_add = false ;
    vlan_config_del->interface = "Ethernet12";
    vlan_config_del->vlan = "Vlan100";

    event.msg = static_cast<void *>(vlan_config_del);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_NE(vlan_map["Ethernet12"], "Vlan100");
    EXPECT_GE(vlans["Vlan100"].client_sock, 0);

    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST(relayConfig, handle_vlan_interface_events) {
    struct ifaddrs *mock_ifaddrs = CreateMockIfaddrs("192.168.5.5", "255.255.255.0", "Vlan100", "192.168.1.2", "Ethernet4");
    int pipe_fds[2];
    EXPECT_GLOBAL_CALL(getifaddrs, getifaddrs(_)).WillOnce(DoAll(testing::SetArgPointee<0>(mock_ifaddrs), Return(0)));
    EXPECT_GLOBAL_CALL(freeifaddrs, freeifaddrs(_)).Times(1);
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Invoke(RealWrite));
    ASSERT_NE(pipe(pipe_fds), -1);

    std::unordered_map<std::string, relay_config> vlans;
    vlans["Vlan100"].vlan = "Vlan100";
    vlans["Vlan100"].is_add = true;

    vlan_interface_config *vlan_config = new vlan_interface_config();

    vlan_config->vlan = "Vlan100";
    vlan_config->vrf = "VrfRed";

    event_config event;
    event.type = DHCPv4_RELAY_VLAN_INTERFACE_UPDATE;
    event.msg = static_cast<void *>(vlan_config);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_EQ(vlan_vrf_map["Vlan100"], "VrfRed");

    vlan_interface_config *vlan_intf_config = new vlan_interface_config();

    vlans["Vlan100"].client_sock = -1;
    vlan_intf_config->vlan = "Vlan100";

    event.msg = static_cast<void *>(vlan_intf_config);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_GE(vlans["Vlan100"].client_sock, 0);
    EXPECT_EQ(vlans["Vlan100"].link_address.sin_addr.s_addr, inet_addr("192.168.5.5"));
    EXPECT_EQ(vlans["Vlan100"].link_address_netmask.sin_addr.s_addr, inet_addr("255.255.255.0"));

    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST(relayConfig, handle_port_table_events) {
    int pipe_fds[2];
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Invoke(RealWrite));
    ASSERT_NE(pipe(pipe_fds), -1);
    std::unordered_map<std::string, relay_config> vlans;

    port_config *port_msg = new port_config();

    port_msg->phy_interface = "Ethernet12";
    port_msg->alias = "eth12";
    port_msg->is_add = true;

    event_config event;
    event.type = DHCPv4_RELAY_PORT_UPDATE;
    event.msg = static_cast<void *>(port_msg);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);

    EXPECT_EQ(interface_list[0], "Ethernet12");
    EXPECT_EQ(phy_interface_alias_map["Ethernet12"], "eth12");

    port_config *port_msg_del = new port_config();

    port_msg_del->phy_interface = "Ethernet12";
    port_msg_del->is_add = false;

    event.msg = static_cast<void *>(port_msg_del);

    ASSERT_NE(write(pipe_fds[1], &event, sizeof(event)), -1);

    config_event_callback(pipe_fds[0], 0, &vlans);
    EXPECT_EQ(std::find(interface_list.begin(), interface_list.end(), "Ethernet12"), interface_list.end());
    EXPECT_EQ(phy_interface_alias_map.count("Ethernet12"), 0);

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

TEST(DHCPMgrTest, initialize_config_listener) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(-1));
    dhcpMgr.initialize_config_listener();
    
    swss::Table dhcp_table(config_db.get(), "DHCPV4_RELAY");
    swss::Table intf_table(config_db.get(), "INTERFACE");
    swss::Table loopback_intf_table(config_db.get(), "LOOPBACK_INTERFACE");
    swss::Table portchannel_intf_table(config_db.get(), "PORTCHANNEL_INTERFACE");
    swss::Table metadata_table(config_db.get(), "DEVICE_METADATA");
    swss::Table vlan_member_table(config_db.get(), "VLAN_MEMBER");
    swss::Table vlan_interface_table(config_db.get(), "VLAN_INTERFACE");
    swss::Table port_table(config_db.get(), "PORT");

    std::string vlan_member_key = "Vlan200|Ethernet8";
    std::vector<std::pair<std::string, std::string>> vlan_member_values = {
            {"tagging_mode", "untagged"},
    };
   
    std::string vlan_interface_key = "Vlan200|200.200.200.1/24";
    std::vector<std::pair<std::string, std::string>> vlan_interface_values = {
            {"vrf_name", "VrfRed"},
    };

    std::string vlan = "Vlan200";
    std::vector<std::pair<std::string, std::string>> dhcp_values = {
            {"dhcpv4_servers", "1.1.1.1,1.1.1.2"},
	    {"server_vrf", "VrfRed"},
            {"source_interface", "Ethernet4"},
	    {"agent_relay_mode", "discard"},
	    {"link_selection", "enable"},
	    {"server_id_override", "enable"},
	    {"vrf_selection", "enable"},
	    {"max_hop_count", "16"}
    };

    dhcp_table.set(vlan, dhcp_values);

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

    std::vector<std::pair<std::string, std::string>> port_values = {
            {"alias", "eth12"},
    };
    metadata_table.set("host", metadata_values);
    metadata_table.set(metadata_key, metadata_values);
    vlan_member_table.set(vlan_member_key, vlan_member_values);
    vlan_interface_table.set(vlan_interface_key, intf_values);
    vlan_interface_table.set(vlan, vlan_interface_values);
    port_table.set("Ethernet12", port_values);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    dhcpMgr.stop_db_updates();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(vlans_copy[vlan].max_hop_count, 16);
}

TEST(DHCPMgrTest, process_vlan_events) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(-1));
    vlans_copy.clear();
    relay_config *config = new relay_config();
    config->vlan = "Vlan100";
    config->is_add = true;
    vlans_copy["Vlan100"] = *config;
    std::deque<swss::KeyOpFieldsValuesTuple> entries;
    entries.emplace_back("Vlan100", "SET", std::vector<swss::FieldValueTuple>{}); 
    dhcpMgr.process_vlan_notification(entries);
}

TEST(DHCPMgrTest, dhcp_server_feature_enable) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(0));
    dhcpMgr.initialize_config_listener();

    std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);

    swss::Table feature_table(config_db.get(), "FEATURE");
    swss::Table vlan_table(config_db.get(), "VLAN");
    swss::Table dhcp_server_table(config_db.get(), "DHCP_SERVER_IPV4");
    swss::Table dhcp_server_ip_table(state_db.get(), "DHCP_SERVER_IPV4_SERVER_IP");

    std::string vlan = "Vlan200";
    std::vector<std::pair<std::string, std::string>> enable_dhcp_server = {
            {"state", "enabled"},
    };

    std::vector<std::pair<std::string, std::string>> server_ip_values = {
            {"ip", "240.127.1.2"},
    };
    
    std::vector<std::pair<std::string, std::string>> vlan_values = {
            {"vlanid", "200"},
    };

    vlan_table.set(vlan, vlan_values);
    dhcp_server_ip_table.set("eth0", server_ip_values);
    dhcp_server_table.set(vlan, enable_dhcp_server);
    feature_table.set("dhcp_server", enable_dhcp_server);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    dhcpMgr.stop_db_updates();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(global_dhcp_server_ip, "240.127.1.2");
    feature_dhcp_server_enabled = false;
    global_dhcp_server_ip.clear();
}

TEST(DHCPMgrTest, dhcp_server_feature_disable) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(0));
    dhcpMgr.initialize_config_listener();

    swss::Table feature_table(config_db.get(), "FEATURE");
    std::vector<std::pair<std::string, std::string>> disable_dhcp_server = {
            {"state", "disabled"},
    };
    feature_dhcp_server_enabled = true;
    feature_table.set("dhcp_server", disable_dhcp_server);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    dhcpMgr.stop_db_updates();;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    feature_dhcp_server_enabled = false;
}

TEST(DHCPMgrTest, dhcp_server_ip_modification) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(0));
    global_dhcp_server_ip = "240.127.1.3";
    std::deque<swss::KeyOpFieldsValuesTuple> entries;
    swss::Select select;
    entries.emplace_back("eth0", "SET", std::vector<swss::FieldValueTuple>{
        {"ip", "240.127.1.2"}
    });

    dhcpMgr.process_dhcp_server_ipv4_ip_notification(entries, select, config_db);
    EXPECT_EQ(global_dhcp_server_ip, "240.127.1.2");
}

TEST(DHCPMgrTest, dhcp_server_ip_deletion) {
    DHCPMgr dhcpMgr;
    EXPECT_GLOBAL_CALL(write, write(_, _, _))
                     .Times(AtLeast(1))
                     .WillRepeatedly(Return(0));
    std::deque<swss::KeyOpFieldsValuesTuple> entries;
    swss::Select select;
    entries.emplace_back("eth0", "DEL", std::vector<swss::FieldValueTuple>{});

    dhcpMgr.process_dhcp_server_ipv4_ip_notification(entries, select,config_db);
    EXPECT_TRUE(global_dhcp_server_ip.empty());
    EXPECT_TRUE(vlans_copy.empty());
}

TEST(DHCPRelayTest, encode_relay_option) {
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));

    pcpp::IPv4Address srcIp("172.22.178.234");
    pcpp::IPv4Address dstIp("10.10.8.240");
    pcpp::IPv4Layer ipLayer(srcIp, dstIp);
    ipLayer.getIPv4Header()->ipId = htobe16(20370);
    ipLayer.getIPv4Header()->timeToLive = 128;

    pcpp::UdpLayer udpLayer((uint16_t)67, (uint16_t)67);

    pcpp::MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
    pcpp::DhcpLayer dhcpLayer(pcpp::DHCP_DISCOVER, clientMac);
    dhcpLayer.getDhcpHeader()->hops = 1;

    interface_list.push_back("Ethernet12");
    phy_interface_alias_map["Ethernet12"] = "eth12";

    relay_config config = {};
    config.phy_interface = "Ethernet12";
    config.vlan = "Vlan10";
    config.link_selection_opt = "enable";
    config.server_id_override_opt = "enable";
    config.link_address.sin_addr.s_addr = inet_addr("192.168.10.10");
    config.link_address_netmask.sin_addr.s_addr = inet_addr("255.255.255.0");
    config.vrf_selection_opt = "enable";
    vlan_vrf_map["Vlan10"] = "Vrf01";

    m_config.hostname = "cisco";
    m_config.host_mac_addr = "12:32:54:24:95:36";

    encode_relay_option(&dhcpLayer, &config);

    auto agent_option = dhcpLayer.getOptionData(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
    auto options_ptr = agent_option.getValue();
    auto agent_option_size = agent_option.getDataSize();
    EXPECT_NE((uintptr_t)options_ptr, NULL);

    uint8_t circuit_id_len = 0;
    auto circuit_id_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_CIRCUIT_ID,
                                 circuit_id_len, agent_option_size);
    std::string circuit_id((const char*)circuit_id_ptr, circuit_id_len);

    EXPECT_EQ(circuit_id, "cisco:eth12:Vlan10");
    uint8_t remote_id_len = 0;
    auto remote_id_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_REMOTE_ID,
                               remote_id_len, agent_option_size);

    EXPECT_EQ(memcmp(m_config.host_mac_addr.c_str(), remote_id_ptr, 17), 0);

    uint8_t link_sel_len = 0;
    auto link_sel_ip_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_LINK_SELECTION,
                                        link_sel_len, agent_option_size);
    auto link_sel_ip = *((uint32_t *)link_sel_ip_ptr);
    EXPECT_EQ((config.link_address.sin_addr.s_addr & config.link_address_netmask.sin_addr.s_addr), link_sel_ip);

    auto srv_ovr_ride = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_SERVER_OVERRIDE,
                                    link_sel_len, agent_option_size);
    auto srv_ip = *((uint32_t *)srv_ovr_ride);
    EXPECT_EQ(srv_ip, config.link_address.sin_addr.s_addr);

    uint8_t vrf_len = 0;
    auto vrf_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_VIRTUAL_SUBNET,
                           vrf_len, agent_option_size);
    std::string vrf((char *)vrf_ptr, vrf_len);
    uint8_t vss_buf[32] = {0};
    uint8_t zero_encode = 0;
    memcpy(vss_buf, &zero_encode, sizeof(uint8_t));
    memcpy((vss_buf + 1), (uint8_t*)vlan_vrf_map["Vlan10"].c_str(), (uint8_t)vlan_vrf_map["Vlan10"].length());

    EXPECT_EQ(memcmp(vss_buf, vrf_ptr, 6), 0);
}

TEST(DHCPRelayTest, encode_relay_option_server_client_same_vrf) {
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));

    pcpp::IPv4Address srcIp("172.22.178.234");
    pcpp::IPv4Address dstIp("10.10.8.240");
    pcpp::IPv4Layer ipLayer(srcIp, dstIp);
    ipLayer.getIPv4Header()->ipId = htobe16(20370);
    ipLayer.getIPv4Header()->timeToLive = 128;

    pcpp::UdpLayer udpLayer((uint16_t)67, (uint16_t)67);

    pcpp::MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
    pcpp::DhcpLayer dhcpLayer(pcpp::DHCP_DISCOVER, clientMac);
    dhcpLayer.getDhcpHeader()->hops = 1;

    interface_list.push_back("Ethernet12");
    phy_interface_alias_map["Ethernet12"] = "eth12";

    relay_config config = {};
    config.phy_interface = "Ethernet12";
    config.vlan = "Vlan10";
    config.vrf = "Vrf01";
    config.link_selection_opt = "enable";
    config.server_id_override_opt = "enable";
    config.link_address.sin_addr.s_addr = inet_addr("192.168.10.10");
    config.link_address_netmask.sin_addr.s_addr = inet_addr("255.255.255.0");
    config.vrf_selection_opt = "enable";
    vlan_vrf_map["Vlan10"] = "Vrf01";

    m_config.hostname = "cisco";
    m_config.host_mac_addr = "12:32:54:24:95:36";

    encode_relay_option(&dhcpLayer, &config);

    auto agent_option = dhcpLayer.getOptionData(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
    auto options_ptr = agent_option.getValue();
    auto agent_option_size = agent_option.getDataSize();
    EXPECT_NE((uintptr_t)options_ptr, NULL);

    uint8_t circuit_id_len = 0;
    auto circuit_id_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_CIRCUIT_ID,
                                 circuit_id_len, agent_option_size);
    std::string circuit_id((const char*)circuit_id_ptr, circuit_id_len);

    EXPECT_EQ(circuit_id, "cisco:eth12:Vlan10");
    uint8_t remote_id_len = 0;
    auto remote_id_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_REMOTE_ID,
                               remote_id_len, agent_option_size);

    EXPECT_EQ(memcmp(m_config.host_mac_addr.c_str(), remote_id_ptr, 17), 0);

    uint8_t link_sel_len = 0;
    auto link_sel_ip_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_LINK_SELECTION,
                                        link_sel_len, agent_option_size);
    auto link_sel_ip = *((uint32_t *)link_sel_ip_ptr);
    EXPECT_EQ((config.link_address.sin_addr.s_addr & config.link_address_netmask.sin_addr.s_addr), link_sel_ip);

    auto srv_ovr_ride = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_SERVER_OVERRIDE,
                                    link_sel_len, agent_option_size);
    auto srv_ip = *((uint32_t *)srv_ovr_ride);
    EXPECT_EQ(srv_ip, config.link_address.sin_addr.s_addr);

    uint8_t vrf_len = 0;
    uint8_t *vrf_ptr = NULL;
    vrf_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_VIRTUAL_SUBNET,
                           vrf_len, agent_option_size);

    EXPECT_EQ((uintptr_t)vrf_ptr, NULL);
}

TEST(DHCPRelayTest, to_client) {
    pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
    std::unordered_map<std::string, relay_config> vlans;

    pcpp::IPv4Address srcIp("172.22.178.234");
    pcpp::IPv4Address dstIp("10.10.8.240");
    pcpp::IPv4Layer ipLayer(srcIp, dstIp);
    ipLayer.getIPv4Header()->ipId = htobe16(20370);
    ipLayer.getIPv4Header()->timeToLive = 128;

    pcpp::UdpLayer udpLayer((uint16_t)67, (uint16_t)67);

    pcpp::MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
    pcpp::DhcpLayer dhcpLayer(pcpp::DHCP_OFFER, clientMac);
    dhcpLayer.getDhcpHeader()->hops = 1;
    dhcpLayer.getDhcpHeader()->gatewayIpAddress = inet_addr("192.168.1.1");
    dhcpLayer.getDhcpHeader()->opCode = 1;

    interface_list.push_back("Ethernet12");
    phy_interface_alias_map["Ethernet12"] = "eth12";

    relay_config config = {};
    config.phy_interface = "Ethernet12";
    config.vlan = "Vlan10";
    config.link_selection_opt = "enable";
    config.server_id_override_opt = "enable";
    config.link_address.sin_addr.s_addr = inet_addr("192.168.10.10");
    config.link_address_netmask.sin_addr.s_addr = inet_addr("255.255.255.0");
    config.vrf_selection_opt = "enable";
    vlan_vrf_map["Vlan10"] = "Vrf01";

    m_config.host_mac_addr = "12:32:54:24:95:36";
    vlans["Vlan10"] = config;
    encode_relay_option(&dhcpLayer, &config);

    struct ifaddrs *mock_ifaddrs = CreateMockIfaddrs("192.168.1.1", "255.255.255.0", "Vlan100", "192.168.1.2", "Ethernet4");
    EXPECT_GLOBAL_CALL(getifaddrs, getifaddrs(_)).WillOnce(DoAll(testing::SetArgPointee<0>(mock_ifaddrs), Return(0)));
    EXPECT_GLOBAL_CALL(freeifaddrs, freeifaddrs(_)).Times(1);
    EXPECT_GLOBAL_CALL(send_udp, send_udp(_, _, _, _, _, _)).WillOnce([]
		(int sock, uint8_t* hdr, struct sockaddr_in target, uint32_t len, in_addr src_ip, bool use_src_ip) {
        pcpp::dhcp_header* dhcp_hdr = (pcpp::dhcp_header*)hdr;
        EXPECT_EQ((dhcp_hdr->opCode), 1);
        EXPECT_EQ((dhcp_hdr->hops), 1);
        EXPECT_EQ((dhcp_hdr->gatewayIpAddress), inet_addr("192.168.1.1"));
        return true;
    });
    to_client(&dhcpLayer, &vlans, "172.22.178.234");
}

TEST(DHCPRelayTest, from_client) {

    pcpp::MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
    pcpp::DhcpLayer dhcpLayer(pcpp::DHCP_DISCOVER, clientMac);
    dhcpLayer.getDhcpHeader()->hops = 0;
    dhcpLayer.getDhcpHeader()->gatewayIpAddress = inet_addr("192.168.1.1");
    dhcpLayer.getDhcpHeader()->opCode = 0;

    interface_list.push_back("Ethernet12");
    phy_interface_alias_map["Ethernet12"] = "eth12";

    relay_config config = {};
    config.phy_interface = "Ethernet12";
    config.vlan = "Vlan10";
    config.link_selection_opt = "enable";
    config.server_id_override_opt = "enable";
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("192.168.20.100");
    config.servers_sock = {addr};
    config.servers = {"192.168.20.100"};
    config.link_address.sin_addr.s_addr = inet_addr("192.168.10.10");
    config.link_address_netmask.sin_addr.s_addr = inet_addr("255.255.255.0");
    config.vrf_selection_opt = "enable";
    vlan_vrf_map["Vlan10"] = "Vrf01";

    m_config.host_mac_addr = "12:32:54:24:95:36";
    encode_relay_option(&dhcpLayer, &config);

    EXPECT_GLOBAL_CALL(send_udp, send_udp(_, _, _, _, _, _)).WillOnce([]
		    (int sock, uint8_t* hdr, struct sockaddr_in target, uint32_t len, in_addr src_ip, bool use_src_ip) {
        pcpp::dhcp_header* dhcp_hdr = (pcpp::dhcp_header*)hdr;
        EXPECT_EQ((dhcp_hdr->opCode), 0);
        EXPECT_EQ((dhcp_hdr->hops), 1);
        EXPECT_EQ((dhcp_hdr->gatewayIpAddress), inet_addr("192.168.1.1"));
        return true;
    });
    from_client(&dhcpLayer, config);
}
