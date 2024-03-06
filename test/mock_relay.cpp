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

using namespace ::testing;

bool dual_tor_sock = false;
char loopback[IF_NAMESIZE] = "Loopback0";
int mock_sock = 124;

static struct sock_filter ether_relay_filter[] = {

    { 0x28, 0, 0, 0xfffff004 },
    { 0x15, 15, 0, 0x00000004 },
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 13, 0x000086dd },
    { 0x20, 0, 0, 0x00000026 },
    { 0x15, 0, 11, 0xff020000 },
    { 0x20, 0, 0, 0x0000002a },
    { 0x15, 0, 9, 0x00000000 },
    { 0x20, 0, 0, 0x0000002e },
    { 0x15, 0, 7, 0x00000000 },
    { 0x20, 0, 0, 0x00000032 },
    { 0x15, 0, 5, 0x00010002 },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 3, 0x00000011 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 0, 1, 0x00000223 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};
const struct sock_fprog ether_relay_fprog = {
        lengthof(ether_relay_filter),
        ether_relay_filter
};

/* sudo tcpdump -dd -i lo port 547 */
static struct sock_filter lo_ether_relay_filter[] = {

    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 8, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 17, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 14, 0, 0x00000223 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 12, 13, 0x00000223 },
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000223 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000223 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};
const struct sock_fprog lo_ether_relay_fprog = {
        lengthof(lo_ether_relay_filter),
        lo_ether_relay_filter
};

TEST(helper, toString)
{
    EXPECT_EQ("0", toString(0));
}

TEST(parsePacket, parse_ether_frame)
{
  unsigned char ether[] = {
      0x33, 0x33, 0x00, 0x01, 0x00, 0x02,   /* destination address  */
      0xfe, 0x54, 0x00, 0x7e, 0x13, 0x01,   /* source address   */
      0x86, 0xdd, 0x60                      /* layer3 ipv6 protocol */
  };

  char *ptr = (char *)ether;
  const uint8_t *tmp = NULL;
  const uint8_t *current_position = (uint8_t *)ptr;
  auto ether_header = parse_ether_frame(current_position, &tmp);
  
  EXPECT_EQ(0x33, ether_header->ether_dhost[0]);
  EXPECT_EQ(0x33, ether_header->ether_dhost[1]);
  EXPECT_EQ(0x00, ether_header->ether_dhost[2]);
  EXPECT_EQ(0x01, ether_header->ether_dhost[3]);
  EXPECT_EQ(0x00, ether_header->ether_dhost[4]);
  EXPECT_EQ(0x02, ether_header->ether_dhost[5]);

  EXPECT_EQ(0xfe, ether_header->ether_shost[0]);
  EXPECT_EQ(0x54, ether_header->ether_shost[1]);
  EXPECT_EQ(0x00, ether_header->ether_shost[2]);
  EXPECT_EQ(0x7e, ether_header->ether_shost[3]);
  EXPECT_EQ(0x13, ether_header->ether_shost[4]);
  EXPECT_EQ(0x01, ether_header->ether_shost[5]);

  EXPECT_EQ(ntohs(ETHERTYPE_IPV6), ether_header->ether_type);
}

TEST(parsePacket, parse_ip6_hdr)
{
  unsigned char ip6[] = { 
      0x60, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x11, 0x40, 0xfe, 0x80,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x32, 0x20, 0xff, 0xfe, 0xe6, 0x27, 0x00, 0xff, 0x02,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02
};

  char *ptr = (char *)ip6;
  std::string dest_addr;
  std::string src_addr;
  char dst[INET6_ADDRSTRLEN];
  char src[INET6_ADDRSTRLEN];
  const uint8_t *current_position = (uint8_t *)ptr;
  const uint8_t *tmp = NULL;

  auto ip6_header = parse_ip6_hdr(current_position, &tmp);
  inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst, sizeof(dst));
  inet_ntop(AF_INET6, &ip6_header->ip6_src, src, sizeof(src));
  EXPECT_EQ("ff02::1:2", dest_addr.append(dst)); 
  EXPECT_EQ("fe80::c032:20ff:fee6:2700", src_addr.append(src));
} 

TEST(parsePacket, parse_udp)
{
  unsigned char udp[] = {     /* UDP Header */
      0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 0x01, 0x00, 
      0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 0x01, 0x00, 
      0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 0x01, 0x00, 
      0x30, 0x39 
  };

  char *ptr = (char *)udp;
  const uint8_t *current_position = (uint8_t *)ptr;
  const uint8_t *tmp = NULL;

  auto udp_header = parse_udp(current_position, &tmp);
  EXPECT_EQ(547, ntohs(udp_header->uh_dport));
  EXPECT_EQ(546, ntohs(udp_header->uh_sport));
  EXPECT_EQ(12, ntohs(udp_header->len));
}

TEST(parsePacket, parse_dhcpv6_hdr)
{
  unsigned char dhcpv6_hdr[] = {    /* DHCPv6 Header */
      0x01, 0x00, 0x30, 0x39 
  };
  
  char *ptr = (char *)dhcpv6_hdr;
  const uint8_t *current_position = (uint8_t *)ptr;

  auto msg = parse_dhcpv6_hdr(current_position);
  EXPECT_EQ(1, msg->msg_type);
}

TEST(parsePacket, parse_dhcpv6_relay)
{
  unsigned char relay[] = {     /* DHCPv6 Relay-Forward Header  */
      0x0c, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x83, 0xef, 0xff, 0xfe, 0x51,
      0x56, 0x52, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xdf, 0xa8, 0x01, 0xac, 0xb7,
      0x08, 0x86, 0x00, 0x09, 0x00, 0x63
  }; 

  char *ptr = (char *)relay;
  std::string link_addr;
  std::string peer_addr;
  char peer[INET6_ADDRSTRLEN];
  char link[INET6_ADDRSTRLEN];

  const uint8_t *current_position = (uint8_t *)ptr;
  auto dhcp_relay_header = parse_dhcpv6_relay(current_position);
  inet_ntop(AF_INET6, &dhcp_relay_header->peer_address, peer, sizeof(peer));
  inet_ntop(AF_INET6, &dhcp_relay_header->link_address, link, sizeof(link));
  EXPECT_EQ(0, dhcp_relay_header->hop_count);
  EXPECT_EQ(12, dhcp_relay_header->msg_type);
  EXPECT_GE("fe80::7683:efff:fe51:5652", link_addr.append(link)); 
  EXPECT_GE("fe80::58df:a801:acb7:886", peer_addr.append(peer)); 
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

TEST(helper, send_udp)
{
  int sock = 0;
  uint8_t buffer[4096];
  struct sockaddr_in6 target;
  target.sin6_family = AF_INET6;
  target.sin6_flowinfo = 0;
  target.sin6_port = htons(RELAY_PORT);
  target.sin6_scope_id = 0; 
  inet_pton(AF_INET6, "::1", &target.sin6_addr);
  uint32_t len = 10;
  send_udp(sock, buffer, target, len);
  EXPECT_EQ(1, sendUdpCount);
  sendUdpCount = 0;
}

TEST(prepareConfig, prepare_relay_config)
{
  int gua_sock = 1;
  int filter = 1;
  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

  struct ip6_hdr ip_hdr;
  std::string s_addr = "fe80::1";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);

  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");

  config.interface = "Vlan1000";
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  config.state_db = state_db;

  prepare_relay_config(config, gua_sock, filter);

  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(config.servers_sock.at(0).sin6_addr), addr1, sizeof(addr1));
  inet_ntop(AF_INET6, &(config.servers_sock.at(1).sin6_addr), addr2, sizeof(addr2));
  std::string s1(addr1);
  std::string s2(addr2);
  
  EXPECT_EQ("fc02:2000::1", s1);
  EXPECT_EQ("fc02:2000::2", s2);
}

TEST(prepareConfig, prepare_lo_socket)
{
  // test case use "lo" as an example
  std::string ifname1 = "lo";
  std::string ifname2 = "lo222";

  auto sock = prepare_lo_socket(ifname1.c_str());

  struct ifaddrs *ifa, *ifa_tmp;
  if (getifaddrs(&ifa) == -1) {
    EXPECT_EQ(sock, -1);
  }
  bool find_gua = false;
  ifa_tmp = ifa;
  while (ifa_tmp) {
    if (ifa_tmp->ifa_addr && (ifa_tmp->ifa_addr->sa_family == AF_INET6)) {
      if (strcmp(ifa_tmp->ifa_name, ifname1.c_str()) == 0) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
        if (!IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
          find_gua = true;
        }
      }
    }
    ifa_tmp = ifa_tmp->ifa_next;
  }
  freeifaddrs(ifa);
  if (find_gua) 
    EXPECT_GE(sock, 0);
  else
    EXPECT_EQ(sock, -1);

  sock = prepare_lo_socket(ifname2.c_str());
  EXPECT_EQ(sock, -1);
}

TEST(prepareConfig, prepare_vlan_sockets)
{
  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

  struct ip6_hdr ip_hdr;
  std::string s_addr = "fe80::1";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);

  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");

  config.interface = "Vlan1000";
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  config.state_db = state_db;

  int gua_sock = -1, lla_sock = -1;
  prepare_vlan_sockets(gua_sock, lla_sock, config);

  EXPECT_GE(gua_sock, 0);
  EXPECT_GE(lla_sock, 0);
}

TEST(counter, initialize_counter)
{
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  std::string ifname = "Vlan1000";
  initialize_counter(state_db, ifname);
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Unknown"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Advertise"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Request"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Confirm"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Renew"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Rebind"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Reply"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Release"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Decline"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Relay-Forward"));
  EXPECT_TRUE(state_db->hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Relay-Reply"));
}

TEST(counter, increase_counter)
{
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  state_db->hset("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit", "0");
  std::string ifname = "Vlan1000";
  increase_counter(state_db, ifname, 1);
  std::shared_ptr<std::string> output = state_db->hget("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit");
  std::string *ptr = output.get();
  EXPECT_EQ(*ptr, "1");
}

TEST(relay, relay_client) 
{
  uint8_t msg[] = {
      0x01, 0x2f, 0xf4, 0xc8, 0x00, 0x01, 0x00, 0x0e,
      0x00, 0x01, 0x00, 0x01, 0x25, 0x3a, 0x37, 0xb9,
      0x5a, 0xc6, 0xb0, 0x12, 0xe8, 0xb4, 0x00, 0x06,
      0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08,
      0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c,
      0xb0, 0x12, 0xe8, 0xb4, 0x00, 0x00, 0x0e, 0x10,
      0x00, 0x00, 0x15, 0x18
  };
  int32_t msg_len = sizeof(msg);

  struct relay_config config{};
  config.is_option_79 = true;
  config.is_interface_id = true;
  config.gua_sock = mock_sock;
  config.lla_sock = mock_sock;
  config.lo_sock = mock_sock;
  std::vector<std::string> servers;
  servers.push_back("fc02:2000::1");
  servers.push_back("fc02:2000::2");
  for (auto server:servers) {
    sockaddr_in6 tmp;
    inet_pton(AF_INET6, server.c_str(), &tmp.sin6_addr);
    tmp.sin6_family = AF_INET6;
    tmp.sin6_flowinfo = 0;
    tmp.sin6_port = htons(RELAY_PORT);
    tmp.sin6_scope_id = 0;
    config.servers_sock.push_back(tmp);
  }
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  config.state_db = state_db;

  struct ether_header ether_hdr;
  ether_hdr.ether_shost[0] = 0x5a;
  ether_hdr.ether_shost[1] = 0xc6;
  ether_hdr.ether_shost[2] = 0xb0;
  ether_hdr.ether_shost[3] = 0x12;
  ether_hdr.ether_shost[4] = 0xe8;
  ether_hdr.ether_shost[5] = 0xb4;

  ip6_hdr ip_hdr;
  std::string s_addr = "2000::3";

  // invalid msg_len testing
  ASSERT_NO_THROW(relay_client(msg, 2, &ip_hdr, &ether_hdr, &config));

  // packet with a super length > sizeof(msg)
  EXPECT_DEATH(relay_client(msg, 65535, &ip_hdr, &ether_hdr, &config), "");

  // normal packet testing
  dual_tor_sock = true;
  ASSERT_NO_THROW(relay_client(msg, msg_len, &ip_hdr, &ether_hdr, &config));

  EXPECT_EQ(last_used_sock, mock_sock);

  auto sent_msg = parse_dhcpv6_relay(sender_buffer);

  EXPECT_EQ(sent_msg->msg_type, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
  EXPECT_EQ(sent_msg->hop_count, 0);

  for (int i = 0; i < 16; i++) {
      EXPECT_EQ(sent_msg->link_address.__in6_u.__u6_addr8[i], config.link_address.sin6_addr.__in6_u.__u6_addr8[i]);
      EXPECT_EQ(sent_msg->peer_address.__in6_u.__u6_addr8[i], ip_hdr.ip6_src.__in6_u.__u6_addr8[i]);
  }
}

TEST(relay, relay_relay_forw) {
  uint8_t msg[] = {
      0x0c, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x5a,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x09, 0x00, 0x34, 0x01, 0x2f,
      0xf4, 0xc8, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01,
      0x00, 0x01, 0x25, 0x3a, 0x37, 0xb9, 0x5a, 0xc6,
      0xb0, 0x12, 0xe8, 0xb4, 0x00, 0x06, 0x00, 0x04,
      0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0xb0, 0x12,
      0xe8, 0xb4, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
      0x15, 0x18
  };
  int32_t msg_len = sizeof(msg);

  relay_config config{};
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x02;
  std::vector<std::string> servers;
  servers.push_back("fc02:2000::1");
  servers.push_back("fc02:2000::2");
  for (auto server:servers) {
    sockaddr_in6 tmp;
    inet_pton(AF_INET6, server.c_str(), &tmp.sin6_addr);
    tmp.sin6_family = AF_INET6;
    tmp.sin6_flowinfo = 0;
    tmp.sin6_port = htons(RELAY_PORT);
    tmp.sin6_scope_id = 0;
    config.servers_sock.push_back(tmp);
  }
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  config.state_db = state_db;
  config.is_interface_id = true;
  config.gua_sock = mock_sock;
  config.lla_sock = mock_sock;
  config.lo_sock = mock_sock;

  ip6_hdr ip_hdr;
  std::string s_addr = "2000::3";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);

  // msg with hop count > HOP_LIMIT
  auto hop = msg[1];
  msg[1] = 65;
  ASSERT_NO_THROW(relay_relay_forw(msg, msg_len, &ip_hdr, &config));
  msg[1] = hop;

  // super frame over size limit for secondary relay
  uint8_t super_frame[BUFFER_SIZE] = {};
  ::memcpy(super_frame, msg, msg_len);
  ASSERT_NO_THROW(relay_relay_forw(super_frame, BUFFER_SIZE, &ip_hdr, &config));

  // normal packet
  dual_tor_sock = true;
  ASSERT_NO_THROW(relay_relay_forw(msg, msg_len, &ip_hdr, &config));

  EXPECT_EQ(last_used_sock, mock_sock);

  auto sent_msg = parse_dhcpv6_relay(sender_buffer);
  
  EXPECT_EQ(sent_msg->msg_type, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
  EXPECT_EQ(sent_msg->hop_count, 1);
  
  for (int i = 0; i < 16; i++) {
      EXPECT_EQ(sent_msg->link_address.__in6_u.__u6_addr8[i], 0);
      EXPECT_EQ(sent_msg->peer_address.__in6_u.__u6_addr8[i], ip_hdr.ip6_src.__in6_u.__u6_addr8[i]);
  }

  EXPECT_GE(sendUdpCount, 1);
  sendUdpCount = 0;
}

TEST(relay, relay_relay_reply) 
{
  int mock_sock = 123;

  uint8_t msg[] = { 
      0x0d, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x5a,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x12, 0x00, 0x03, 0x47, 0x69,
      0x32, 0x00, 0x09, 0x00, 0x54, 0x07, 0x4f, 0x6d,
      0x04, 0x00, 0x03, 0x00, 0x28, 0xb0, 0x12, 0xe8,
      0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01, 0x0d,
      0xb8, 0x01, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x78, 0x00, 0x00, 0x1c,
      0x20, 0x00, 0x00, 0x1d, 0x4c, 0x00, 0x01, 0x00,
      0x0e, 0x00, 0x01, 0x00, 0x01, 0x25, 0x3a, 0x37,
      0xb9, 0x5a, 0xc6, 0xb0, 0x12, 0xe8, 0xb4, 0x00,
      0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x25,
      0x3a, 0x32, 0x33, 0x50, 0xe5, 0x49, 0x50, 0x9e,
      0x40
  };
  int32_t msg_len = sizeof(msg);

  struct relay_config config{};
  config.is_option_79 = true;

  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

  struct ip6_hdr ip_hdr;
  std::string s_addr = "fe80::1";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);

  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");

  config.interface = "Vlan1000";
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  config.state_db = state_db;
  config.gua_sock = mock_sock;
  config.lla_sock = mock_sock;
  config.lo_sock = mock_sock;

  int gua_sock = 1;
  int filter = 1;

  prepare_relay_config(config, gua_sock, filter);

  // invalid message length
  ASSERT_NO_THROW(relay_relay_reply(msg, 2, &config));

  // invalid relay msg, without OPTION_RELAY_MSG
   uint8_t invalid_msg[] = { 
      0x0d, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x5a,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x12, 0x00, 0x03, 0x47, 0x69,
      0x32, 0x00, 0x10, 0x00, 0x54, 0x07, 0x4f, 0x6d,
      0x04, 0x00, 0x03, 0x00, 0x28, 0xb0, 0x12, 0xe8,
      0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01, 0x0d,
      0xb8, 0x01, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x78, 0x00, 0x00, 0x1c,
      0x20, 0x00, 0x00, 0x1d, 0x4c, 0x00, 0x01, 0x00,
      0x0e, 0x00, 0x01, 0x00, 0x01, 0x25, 0x3a, 0x37,
      0xb9, 0x5a, 0xc6, 0xb0, 0x12, 0xe8, 0xb4, 0x00,
      0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x25,
      0x3a, 0x32, 0x33, 0x50, 0xe5, 0x49, 0x50, 0x9e,
      0x40
  };
  ASSERT_NO_THROW(relay_relay_reply(invalid_msg, msg_len, &config));


  // normal message
  ASSERT_NO_THROW(relay_relay_reply(msg, msg_len, &config));

  EXPECT_EQ(last_used_sock, mock_sock);

  uint8_t expected_bytes[] = {
      0x07, 0x4f, 0x6d, 0x04, 0x00, 0x03, 0x00, 0x28,
      0xb0, 0x12, 0xe8, 0xb4, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x18,
      0x20, 0x01, 0x0d, 0xb8, 0x01, 0x5a, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x78,
      0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x1d, 0x4c,
      0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
      0x25, 0x3a, 0x37, 0xb9, 0x5a, 0xc6, 0xb0, 0x12,
      0xe8, 0xb4, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01,
      0x00, 0x01, 0x25, 0x3a, 0x32, 0x33, 0x50, 0xe5,
      0x49, 0x50, 0x9e, 0x40
  };

  EXPECT_EQ(valid_byte_count, sizeof(expected_bytes));

  EXPECT_EQ(0, memcmp(sender_buffer, expected_bytes, sizeof(expected_bytes)));

  EXPECT_EQ(last_target.sin6_port, htons(CLIENT_PORT));

  in6_addr expected_target;
  inet_pton(AF_INET6, "fe80::1", &expected_target);
  for (int i = 0; i < 16; i++) {
      EXPECT_EQ(last_target.sin6_addr.__in6_u.__u6_addr8[i], expected_target.__in6_u.__u6_addr8[i]);
  }

  EXPECT_GE(sendUdpCount, 1);
  sendUdpCount = 0;
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

MOCK_GLOBAL_FUNC2(event_base_loopexit, int(struct event_base *, const struct timeval *));

TEST(relay, signal_callback) {
  ASSERT_NO_THROW(signal_callback(1, 1, &base));
  EXPECT_GLOBAL_CALL(event_base_loopexit, event_base_loopexit(_, _));
  signal_callback(SIGTERM, 1, &base);
}

TEST(relay, dhcp6relay_stop) {
  EXPECT_GLOBAL_CALL(event_base_loopexit, event_base_loopexit(_, _));
  ASSERT_NO_THROW(dhcp6relay_stop());
}

TEST(relay, update_vlan_mapping) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("VLAN_MEMBER|Vlan1000|Ethernet19", "tagging_mode", "untagged");
  config_db->hset("VLAN_MEMBER|Vlan1000|Ethernet20", "tagging_mode", "untagged");
  std::string vlan = "Vlan1000";
  update_vlan_mapping(vlan, config_db);

  auto output = config_db->hget("VLAN_MEMBER|Vlan1000|Ethernet19", "tagging_mode");
  std::string *ptr = output.get();
  EXPECT_EQ(*ptr, "untagged");
}

TEST(relay, client_packet_handler) {
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  std::string vlan_name = "Vlan1000";
  initialize_counter(state_db, vlan_name);

  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.state_db = state_db;

  std::string ifname = "Ethernet19";

  uint8_t client_raw_solicit[] = {
    0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x3c, 0x11, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x27, 0xff, 0xfe, 0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x3c, 0xad, 0x08, 0x01, 0x10,
    0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00,
    0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
    0x15, 0x18
  };

  uint8_t client_raw_solicit_invalid_type[] = {
    0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x3c, 0x11, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x27, 0xff, 0xfe, 0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x3c, 0xad, 0x08, 0x00, 0x10,
    0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00,
    0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
    0x15, 0x18
  };

  uint8_t client_raw_solicit_with_externsion[] = {
    0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x44, 0x2c, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x27, 0xff, 0xfe, 0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x11, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
    0x02, 0x22, 0x02, 0x23, 0x00, 0x3c, 0xad, 0x08, 0x01, 0x10,
    0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00,
    0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
    0x15, 0x18
  };
  uint8_t non_udp_with_externsion[] = {
    0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x44, 0x2c, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x27, 0xff, 0xfe, 0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
    0x11, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
    0x02, 0x22, 0x02, 0x23, 0x00, 0x3c, 0xad, 0x08, 0x01, 0x10,
    0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00,
    0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
    0x15, 0x18
  };

  // invalid packet length
  ASSERT_NO_THROW(client_packet_handler(client_raw_solicit, 4, &config, ifname));

  ASSERT_NO_THROW(client_packet_handler(client_raw_solicit, sizeof(client_raw_solicit), &config, ifname));
  
  ASSERT_NO_THROW(client_packet_handler(client_raw_solicit_invalid_type, sizeof(client_raw_solicit_invalid_type), &config, ifname));

  ASSERT_NO_THROW(client_packet_handler(client_raw_solicit_with_externsion, sizeof(client_raw_solicit_with_externsion), &config, ifname));

  ASSERT_NO_THROW(client_packet_handler(non_udp_with_externsion, sizeof(non_udp_with_externsion), &config, ifname));
}

MOCK_GLOBAL_FUNC6(recvfrom, ssize_t(int, void *, size_t, int, struct sockaddr *, socklen_t *));

TEST(relay, server_callback) {
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  std::string ifname = "Vlan1000";
  initialize_counter(state_db, ifname);

  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.state_db = state_db;
  config.gua_sock = -1;
  config.lla_sock = -1;
  config.lo_sock = -1;
  // simulator normal dhcpv6 packet length
  ssize_t msg_len = 129;

  // cover buffer_sz <= 0
  EXPECT_GLOBAL_CALL(recvfrom, recvfrom(_, _, _, _, _, _)).Times(5).WillOnce(Return(0))
    .WillOnce(Return(2)).WillOnce(Return(0))
    .WillOnce(Return(msg_len)).WillOnce(Return(0));
  ASSERT_NO_THROW(server_callback(0, 0, &config));
  // cover 0 < buffer_sz < sizeof(struct dhcpv6_msg)
  ASSERT_NO_THROW(server_callback(0, 0, &config));

  ASSERT_NO_THROW(server_callback(0, 0, &config));
}

MOCK_GLOBAL_FUNC2(if_indextoname, char*(unsigned int, char *));

TEST(relay, client_callback) {
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  std::shared_ptr<swss::Table> mux_table = std::make_shared<swss::Table> (
        state_db.get(), "HW_MUX_CABLE_TABLE"
  );
  std::string ifname = "Vlan1000";
  initialize_counter(state_db, ifname);

  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.state_db = state_db;
  config.mux_table = mux_table;
  config.gua_sock = -1;
  config.lla_sock = -1;
  config.lo_sock = -1;

  std::unordered_map<std::string, struct relay_config> vlans;
  // mock normal dhcpv6 packet length
  ssize_t msg_len = 114;
  std::string vlan1000 = "Vlan1000";
  std::string vlan2000 = "Vlan2000";
  char ethernet1[IF_NAMESIZE] = "Ethernet1";
  char ethernet2[IF_NAMESIZE] = "Ethernet2";
  char ethernet3[IF_NAMESIZE] = "Ethernet3";

  char ptr[20] = "vlan";
  vlans[vlan1000] = config;
  vlan_map["Ethernet1"] = vlan1000;
  vlan_map["Ethernet2"] = vlan2000;

  // negative case testing
  EXPECT_GLOBAL_CALL(recvfrom, recvfrom(_, _, _, _, _, _)).Times(11)
                    .WillOnce(Return(0))
                    .WillOnce(Return(2)).WillOnce(Return(0))
                    .WillOnce(Return(msg_len)).WillOnce(Return(0))
                    .WillOnce(Return(msg_len)).WillOnce(Return(0))
                    .WillOnce(Return(msg_len)).WillOnce(Return(0))
                    .WillOnce(Return(msg_len)).WillOnce(Return(0));

  EXPECT_GLOBAL_CALL(if_indextoname, if_indextoname(_, _)).Times(5).WillOnce(Return(nullptr))
                    .WillOnce(DoAll(SetArrayArgument<1>(ethernet1, ethernet1 + IF_NAMESIZE), Return(ptr)))
                    .WillOnce(DoAll(SetArrayArgument<1>(ethernet2, ethernet2 + IF_NAMESIZE), Return(ptr)))
                    .WillOnce(DoAll(SetArrayArgument<1>(ethernet1, ethernet1 + IF_NAMESIZE), Return(ptr)))
                    .WillOnce(DoAll(SetArrayArgument<1>(ethernet3, ethernet3 + IF_NAMESIZE), Return(ptr)));
  // test buffer_sz <=0 early return
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));
  // test buffer_sz > 0, if_indextoname == null early return
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));
  // test normal msg but vlan not found
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));
  // test normal msg and vlan found 
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));

  dual_tor_sock = true;
  // test normal msg and vlan found + dual tor
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));
  dual_tor_sock = false;
  
  // normal msg but interface mapping missing
  ASSERT_NO_THROW(client_callback(-1, 0, &vlans));
}

TEST(relay, shutdown_relay) {
  signal_init();
  EXPECT_NE((uintptr_t)ev_sigint, NULL);
  EXPECT_NE((uintptr_t)ev_sigterm, NULL);

  ASSERT_NO_THROW(shutdown_relay());
}

TEST(options, Add) {
  class Options options;
  option_interface_id intf_id;
  std::string s_addr = "2001::1000::1";
  inet_pton(AF_INET6, s_addr.c_str(), &intf_id.interface_id);
  EXPECT_TRUE(options.Add(OPTION_INTERFACE_ID, (const uint8_t *)&intf_id.interface_id, sizeof(option_interface_id)));
  auto option_get = options.Get(OPTION_INTERFACE_ID);
  EXPECT_EQ(option_get.size(), sizeof(option_interface_id));
  EXPECT_EQ(std::memcmp(option_get.data(), &intf_id, sizeof(option_interface_id)), 0);
}

TEST(options, Delete) {
  class Options options;
  EXPECT_FALSE(options.Delete(OPTION_INTERFACE_ID));
  option_interface_id intf_id;
  std::string s_addr = "2001::1000::1";
  inet_pton(AF_INET6, s_addr.c_str(), &intf_id.interface_id);
  EXPECT_TRUE(options.Add(OPTION_INTERFACE_ID, (const uint8_t *)&intf_id.interface_id, sizeof(option_interface_id)));
  EXPECT_TRUE(options.Delete(OPTION_INTERFACE_ID));
  EXPECT_EQ(options.Get(OPTION_INTERFACE_ID).size(), 0);
}

TEST(options, Get) {
  class Options options;
  EXPECT_EQ(options.Get(OPTION_INTERFACE_ID).size(), 0);
}

TEST(options, MarshalBinary) {
  class Options options;
  EXPECT_EQ(options.MarshalBinary(), nullptr);
  option_interface_id intf_id;
  std::string s_addr = "2001::1000::1";
  inet_pton(AF_INET6, s_addr.c_str(), &intf_id.interface_id);
  options.Add(OPTION_INTERFACE_ID, (const uint8_t *)&intf_id.interface_id, sizeof(option_interface_id));

  auto op_stream = options.MarshalBinary();
  EXPECT_EQ(op_stream->size(), sizeof(option_interface_id) + 4);

  auto new_op_stream = options.MarshalBinary();
  EXPECT_EQ(new_op_stream, op_stream);
}

TEST(options, UnmarshalBinary) {
  uint8_t option_cid[] = {
    0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
    0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe,
    0x8f, 0x95
  };
  class Options options;
  auto result = options.UnmarshalBinary(option_cid, sizeof(option_cid));
  EXPECT_TRUE(result);
  EXPECT_EQ(options.Get(1).size(), sizeof(option_cid) - 4);

  uint8_t option_invalid_type[] = {
    0x00, 0xff, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
    0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe,
    0x8f, 0x95
  };
  class Options options2;
  result = options2.UnmarshalBinary(option_invalid_type, sizeof(option_invalid_type));
  EXPECT_FALSE(result);

  uint8_t option_invalid_length[] = {
    0x00, 0x01, 0x00, 0xff, 0x00, 0x01, 0x00, 0x01,
    0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe,
    0x8f, 0x95
  };
  class Options options3;
  result = options3.UnmarshalBinary(option_invalid_length, sizeof(option_invalid_length));
  EXPECT_FALSE(result);
}

TEST(relay_msg, MarshalBinary) {
  class RelayMsg relay;
  uint16_t length = 0;

  auto msg = relay.MarshalBinary(length);
  EXPECT_EQ(length, sizeof(dhcpv6_relay_msg));

  uint8_t relay_forward[] = {
      0x0c, 0x00, 0xfc, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x03, 0x9b, 0xff, 0xfe, 0x03,
      0x22, 0x01, 0x00, 0x09, 0x00, 0x36, 0x01, 0x00, 0x30, 0x39, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x4f, 0x00, 0x08,
      0x00, 0x01, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01
  };
  auto result = relay.UnmarshalBinary(relay_forward, sizeof(relay_forward));
  EXPECT_TRUE(result);

  msg = relay.MarshalBinary(length);
  EXPECT_EQ(length, sizeof(relay_forward));

  for (uint16_t i = 0; i < sizeof(relay_forward); i++) {
    EXPECT_EQ(relay_forward[i], msg[i]);
  }
}

TEST(relay_msg, UnmarshalBinary) {
  uint8_t relay_forward[] = {
      0x0c, 0x00, 0xfc, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x03, 0x9b, 0xff, 0xfe, 0x03,
      0x22, 0x01, 0x00, 0x09, 0x00, 0x36, 0x01, 0x00, 0x30, 0x39, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x4f, 0x00, 0x08,
      0x00, 0x01, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01
  };
  class RelayMsg relay;
  auto result = relay.UnmarshalBinary(relay_forward, sizeof(dhcpv6_relay_msg) - 1);
  EXPECT_FALSE(result);

  result = relay.UnmarshalBinary(relay_forward, sizeof(relay_forward));
  EXPECT_TRUE(result);
  EXPECT_EQ(relay.m_msg_hdr.msg_type, 12);
  EXPECT_EQ(relay.m_msg_hdr.hop_count, 0);
  EXPECT_EQ(relay.m_option_list.Get(79).size(), 8);

  uint8_t relay_forward_invalid_opt79[] = {
      0x0c, 0x00, 0xfc, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x03, 0x9b, 0xff, 0xfe, 0x03,
      0x22, 0x01, 0x00, 0x09, 0x00, 0x36, 0x01, 0x00, 0x30, 0x39, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x4f, 0x00, 0xff,
      0x00, 0x01, 0x98, 0x03, 0x9b, 0x03, 0x22, 0x01
  };
  result = relay.UnmarshalBinary(relay_forward_invalid_opt79, sizeof(relay_forward_invalid_opt79));
  EXPECT_FALSE(result);
  EXPECT_EQ(relay.m_msg_hdr.msg_type, 12);
  EXPECT_EQ(relay.m_msg_hdr.hop_count, 0);
}

TEST(dhcpv6_msg, MarshalBinary) {
  class DHCPv6Msg dhcpv6;
  uint16_t length = 0;

  auto msg = dhcpv6.MarshalBinary(length);
  EXPECT_TRUE(msg);
  EXPECT_EQ(length, sizeof(dhcpv6_msg));

  uint8_t solicit[] = {
    0x01, 0x00, 0x30, 0x39, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d,
    0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  auto result = dhcpv6.UnmarshalBinary(solicit, sizeof(solicit));
  EXPECT_TRUE(result);

  msg = dhcpv6.MarshalBinary(length);
  EXPECT_TRUE(msg);
  EXPECT_EQ(length, sizeof(solicit));

  // negative test for marshal error
  class DHCPv6Msg dhcpv6_neg;
  result = dhcpv6_neg.UnmarshalBinary(solicit, sizeof(solicit));
  EXPECT_TRUE(result);

  uint8_t super_frame[65530] = {};

  dhcpv6_neg.m_option_list.Add(100, super_frame, 65530);
  msg = dhcpv6_neg.MarshalBinary(length);
  EXPECT_FALSE(msg);
  EXPECT_FALSE(length);
}

TEST(dhcpv6_msg, UnmarshalBinary) {
  uint8_t solicit[] = {
    0x01, 0x00, 0x30, 0x39, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d,
    0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  class DHCPv6Msg dhcpv6;
  auto result = dhcpv6.UnmarshalBinary(solicit, sizeof(dhcpv6_msg) - 1);
  EXPECT_FALSE(result);

  result = dhcpv6.UnmarshalBinary(solicit, sizeof(solicit));
  EXPECT_TRUE(result);
  EXPECT_EQ(dhcpv6.m_msg_hdr.msg_type, 1);
  EXPECT_EQ(dhcpv6.m_option_list.Get(1).size(), 14);
  EXPECT_EQ(dhcpv6.m_option_list.Get(6).size(), 6);
  EXPECT_EQ(dhcpv6.m_option_list.Get(8).size(), 2);
  EXPECT_EQ(dhcpv6.m_option_list.Get(3).size(), 12);

  uint8_t solicit_invalid_option_cid[] = {
    0x01, 0x00, 0x30, 0x39, 0x00, 0xff, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x03, 0x9b, 0x03, 0x22, 0x01, 0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d,
    0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  result = dhcpv6.UnmarshalBinary(solicit_invalid_option_cid, sizeof(solicit_invalid_option_cid));
  EXPECT_FALSE(result);
  EXPECT_EQ(dhcpv6.m_msg_hdr.msg_type, 1);
}

TEST(relay, loop_relay) {
  std::unordered_map<std::string, relay_config> vlans_in_loop;
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  struct relay_config config{
    .state_db = state_db,
    .interface = "Vlan1000",
    .is_option_79 = true
  };
  vlans_in_loop["Vlan1000"] = config;
  EXPECT_EQ(vlans_in_loop.size(), 1);

  EXPECT_ANY_THROW(loop_relay(vlans_in_loop));
}

TEST(relay, get_relay_int_from_relay_msg) {
  std::string lla_str = "fc02:1000::1";
  std::string vlan_str = "Vlan1000";
  uint8_t relay_reply_with_opt18[] = {
      0x0d,0x00,0xfc,0x02,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x70,0xfd,0xff,0xfe,0xcb,
      0x0c,0x06,0x00,0x09,0x00,0x04,0x07,0x00,0x30,0x39,0x00,0x12,0x00,0x10,0xfc,0x02,
      0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
  };
  uint8_t relay_reply_without_opt18[] = {
      0x0d,0x00,0xfc,0x02,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x70,0xfd,0xff,0xfe,0xcb,
      0x0c,0x06,0x00,0x09,0x00,0x04,0x07,0x00,0x30,0x39
  };
  uint8_t relay_reply_without_opt18_linkaddr_zero[] = {
      0x0d,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x70,0xfd,0xff,0xfe,0xcb,
      0x0c,0x06,0x00,0x09,0x00,0x04,0x07,0x00,0x30,0x39
  };
  std::unordered_map<std::string, relay_config> vlans;
  struct relay_config config{
    .interface = vlan_str,
    .is_option_79 = true,
    .is_interface_id = true
  };

  // valid option18 + invalid name mapping
  auto value = get_relay_int_from_relay_msg(relay_reply_with_opt18, sizeof(relay_reply_with_opt18), &vlans);
  EXPECT_EQ((uintptr_t)value, NULL);

  // valid option18 + valid name mapping + invalid vlan config mapping
  addr_vlan_map[lla_str] = vlan_str;
  value = get_relay_int_from_relay_msg(relay_reply_with_opt18, sizeof(relay_reply_with_opt18), &vlans);
  EXPECT_EQ((uintptr_t)value, NULL);

  // valid option18 + valid name mapping + valid vlan config mapping
  vlans[vlan_str] = config;
  value = get_relay_int_from_relay_msg(relay_reply_with_opt18, sizeof(relay_reply_with_opt18), &vlans);
  EXPECT_NE((uintptr_t)value, NULL);
  EXPECT_EQ(value->interface, vlan_str);

  // no option18 + non-zero link-address + valid name mapping + valid vlan config mapping
  value = get_relay_int_from_relay_msg(relay_reply_without_opt18, sizeof(relay_reply_without_opt18), &vlans);
  EXPECT_NE((uintptr_t)value, NULL);
  EXPECT_EQ(value->interface, vlan_str);

  // no option18 + zero link-address + valid name mapping + valid vlan config mapping
  value = get_relay_int_from_relay_msg(relay_reply_without_opt18_linkaddr_zero, sizeof(relay_reply_without_opt18_linkaddr_zero), &vlans);
  EXPECT_EQ((uintptr_t)value, NULL);
}

TEST(relay, server_callback_dualtor) {
  std::unordered_map<std::string, relay_config> vlans_in_loop;
  std::string ifname = "Vlan1000";
  struct relay_config config{};
  config.is_option_79 = true;
  config.is_interface_id = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.gua_sock = -1;
  config.lla_sock = -1;
  config.lo_sock = -1;
  // simulator normal dhcpv6 packet length
  ssize_t msg_len = 129;

  // cover buffer_sz <= 0
  EXPECT_GLOBAL_CALL(recvfrom, recvfrom(_, _, _, _, _, _)).Times(5)
    .WillOnce(Return(0))
    .WillOnce(Return(2)).WillOnce(Return(0))
    .WillOnce(Return(msg_len)).WillOnce(Return(0));

  ASSERT_NO_THROW(server_callback_dualtor(0, 0, &vlans_in_loop));
  // cover 0 < buffer_sz < sizeof(struct dhcpv6_msg)
  ASSERT_NO_THROW(server_callback_dualtor(0, 0, &vlans_in_loop));
  // normal size and right configuration from get_relay_int_from_relay_msg
  //ASSERT_NO_THROW(server_callback_dualtor(0, 0, &vlans_in_loop));
  // normal size and NULL from get_relay_int_from_relay_msg
  ASSERT_NO_THROW(server_callback_dualtor(0, 0, &vlans_in_loop));
}



