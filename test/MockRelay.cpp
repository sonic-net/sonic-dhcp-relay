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

#include "MockRelay.h"

bool dual_tor_sock = false;
extern struct event_base *base;
extern struct event *ev_sigint;
extern struct event *ev_sigterm;

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

TEST(parsePacket, parse_dhcpv6_opt)
{
  unsigned char relay[] = {     /* Relay-Forward Message DHCPv6 Option */
      0x00, 0x09, 0x00, 0x63, 0x01, 0x34, 0x56, 0x78, 0x00, 0x01, 0x00, 0x0a
  }; 

  char *ptr = (char *)relay;
  const uint8_t *current_position = (uint8_t *)ptr;
  const uint8_t *tmp = NULL;

  auto dhcp_relay_header = parse_dhcpv6_opt(current_position, &tmp);
  EXPECT_EQ(OPTION_RELAY_MSG, ntohs(dhcp_relay_header->option_code));
  EXPECT_EQ(99, ntohs(dhcp_relay_header->option_length));
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
  int local_sock = 1;
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

  prepare_relay_config(config, local_sock, filter);

  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(config.servers_sock.at(0).sin6_addr), addr1, sizeof(addr1));
  inet_ntop(AF_INET6, &(config.servers_sock.at(1).sin6_addr), addr2, sizeof(addr2));
  std::string s1(addr1);
  std::string s2(addr2);
  
  EXPECT_EQ("fc02:2000::1", s1);
  EXPECT_EQ("fc02:2000::2", s2);
}

TEST(prepareConfig, prepare_socket)
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

  int local_sock = -1, server_sock = -1;
  prepare_socket(local_sock, server_sock, config);

  EXPECT_GE(local_sock, 0);

  EXPECT_GE(server_sock, 0);
}


TEST(counter, initialize_counter)
{
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  initialize_counter(state_db, "DHCPv6_COUNTER_TABLE|Vlan1000");
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
  increase_counter(state_db, "DHCPv6_COUNTER_TABLE|Vlan1000", 1);
  std::shared_ptr<std::string> output = state_db->hget("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit");
  std::string *ptr = output.get();
  EXPECT_EQ(*ptr, "1");
}

TEST(relay, relay_client) 
{
  int mock_sock = 124;

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

  relay_client(mock_sock, msg, msg_len, &ip_hdr, &ether_hdr, &config);

  EXPECT_EQ(last_used_sock, 124);

  auto sent_msg = parse_dhcpv6_relay(sender_buffer);

  EXPECT_EQ(sent_msg->msg_type, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
  EXPECT_EQ(sent_msg->hop_count, 0);

  for (int i = 0; i < 16; i++) {
      EXPECT_EQ(sent_msg->link_address.__in6_u.__u6_addr8[i], config.link_address.sin6_addr.__in6_u.__u6_addr8[i]);
      EXPECT_EQ(sent_msg->peer_address.__in6_u.__u6_addr8[i], ip_hdr.ip6_src.__in6_u.__u6_addr8[i]);
  }

  const uint8_t *current_position = sender_buffer + sizeof(dhcpv6_relay_msg);

  bool link_layer = false;
  bool interface_id = false;
  while ((current_position - sender_buffer) < valid_byte_count) {
      
      auto option = parse_dhcpv6_opt(current_position, &current_position);
      switch (ntohs(option->option_code)) {
          case OPTION_RELAY_MSG:
              EXPECT_EQ(memcmp(((uint8_t *)option) + sizeof(dhcpv6_option), msg, msg_len), 0);
          case OPTION_CLIENT_LINKLAYER_ADDR:
              link_layer = true;
          case OPTION_INTERFACE_ID:
                interface_id = true;
      }
  }
  EXPECT_TRUE(link_layer);
  EXPECT_TRUE(interface_id);
  EXPECT_GE(sendUdpCount, 1);
  sendUdpCount = 0;
}

TEST(relay, relay_relay_forw) {
  int mock_sock = 125;

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

  ip6_hdr ip_hdr;
  std::string s_addr = "2000::3";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);

  relay_relay_forw(mock_sock, msg, msg_len, &ip_hdr, &config);

  EXPECT_EQ(last_used_sock, 125);

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

  int local_sock = 1;
  int filter = 1;

  prepare_relay_config(config, local_sock, filter);

  relay_relay_reply(mock_sock, msg, msg_len, &config);

  EXPECT_EQ(last_used_sock, 123);

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

TEST(relay, signal_start) {
  signal_init();
  EXPECT_NE((uintptr_t)ev_sigint, NULL);
  EXPECT_NE((uintptr_t)ev_sigterm, NULL);
  signal_start();
}

TEST(relay, signal_callback) {
  signal_callback(1, 1, &base);
}

TEST(relay, dhcp6relay_stop) {
  int filter = 1;
  std::unordered_map<std::string, struct relay_config> vlans;
  base = event_base_new();
  struct event* event = event_new(base, filter, EV_READ|EV_PERSIST, client_callback,
                                  reinterpret_cast<void *>(&vlans));
  dhcp6relay_stop();
  event_free(event);
  event_base_free(base);
  base = NULL;
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
  initialize_counter(state_db, "DHCPv6_COUNTER_TABLE|Vlan1000");

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

  try {
    // invalid packet length
    client_packet_handler(client_raw_solicit, 4, &config, ifname);

    client_packet_handler(client_raw_solicit, sizeof(client_raw_solicit), &config, ifname);
  
    client_packet_handler(client_raw_solicit_invalid_type, sizeof(client_raw_solicit_invalid_type), &config, ifname);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
  }
}

TEST(relay, server_callback) {
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  initialize_counter(state_db, "DHCPv6_COUNTER_TABLE|Vlan1000");

  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.state_db = state_db;
  config.local_sock = -1;

  // negative case testing
  try {
    server_callback(0, 0, &config);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
  }
}

TEST(relay, client_callback) {
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  initialize_counter(state_db, "DHCPv6_COUNTER_TABLE|Vlan1000");

  struct relay_config config{};
  config.is_option_79 = true;
  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;
  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");
  config.interface = "Vlan1000";
  config.state_db = state_db;
  config.local_sock = -1;

  // negative case testing
  try {
    client_callback(-1, 0, &config);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
  }
}

TEST(relay, loop_relay) {
  std::unordered_map<std::string, relay_config> vlans;
  
  signal_init();
  EXPECT_NE((uintptr_t)ev_sigint, NULL);
  EXPECT_NE((uintptr_t)ev_sigterm, NULL);
  try {
    loop_relay(vlans);
  }
  catch (const std::exception& e) {
    EXPECT_TRUE(false);
  }
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

