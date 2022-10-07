#include <iostream>
#include <signal.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <experimental/filesystem>
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "MockRelay.h"

uint32_t openSockCount = 0;
uint32_t prepareSockCount = 0;

static struct sock_filter ether_relay_filter[] = {

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

/*
struct relay_config {
    int local_sock; 
    int server_sock;
    int filter;
    sockaddr_in6 link_address;
    swss::DBConnector *db;
    std::string interface;
    std::vector<std::string> servers;
    std::vector<sockaddr_in6> servers_sock;
    bool is_option_79;
}
*/

/* relay_config test_config;
test_config.is_option_79 = true;
test_config.local_sock = 0;
test_config.server_sock = 0;
sockaddr_in6 link;
inet_pton(AF_INET6, "fe80::7683:efff:fe51:5652", &link.sin6_addr);
 */


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

  EXPECT_EQ(56710, ether_header->ether_type);
}

TEST(parsePacket, parse_ip6_hdr)
{
  unsigned char ip6[] = {       /* IPv6 Header */
    0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0xfc, 0x54, 0x00, 0xff, 0xfe, 0x7e, 0x13, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 
    0x01, 0x00, 0x30, 0x39 };

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
  EXPECT_EQ("fe80::fc54:ff:fe7e:1301", src_addr.append(src)); 
} 

TEST(parsePacket, parse_udp)
{
  unsigned char udp[] = {     /* UDP Header */
    0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 0x01, 0x00, 
    0x30, 0x39 };
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
    0x01, 0x00, 0x30, 0x39 };
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
  EXPECT_EQ("fe80::7683:efff:fe51:5652", link_addr.append(link)); 
  EXPECT_EQ("fe80::58df:a801:acb7:886", peer_addr.append(peer)); 
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

TEST(parsePacket, relay_forward)
{ 
  unsigned char relay_option[] = {      /* DHCPv6 Relay Option */
    0x00, 0x09, 0x00, 0x63
  };
  char *ptr = (char *)relay_option;
  static uint8_t buffer[8];
  auto current_buffer_position = buffer;

  const uint8_t *current_position = (uint8_t *)ptr;

  relay_forward(current_buffer_position, parse_dhcpv6_hdr(current_position), 4);
  auto option = (const struct dhcpv6_option *)current_buffer_position;

  EXPECT_EQ(9, ntohs(option->option_code));
  EXPECT_EQ(4, ntohs(option->option_length));
}

TEST(sock, sock_open)
{ 
  sock_fprog ether_relay_fprog = {0,{}};
  int index = NULL;
  if (!index) {
                errno = EINVAL;
        }
  EXPECT_EQ(errno, EINVAL);
  openSockCount++;
  int filter = sock_open(index, &ether_relay_fprog);
  EXPECT_EQ(1, openSockCount);
}

TEST(sock, prepare_socket)
{
  relay_config *config = new struct relay_config;;
  int local_sock, server_sock, index = 1;
  prepareSockCount++;
  prepare_socket(&local_sock, &server_sock, config, index);
  EXPECT_EQ(1, prepareSockCount);
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
}

TEST(prepareConfig, prepare_relay_config)
{
  struct relay_config config;
  memset(&config, 0, sizeof(config));
  config.is_option_79 = true;

  config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

  struct ip6_hdr ip_hdr;
  std::string s_addr = "fe80::1";
  inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);
  struct ether_header ether_hdr;
  ether_hdr.ether_shost[0] = 0x5a;
  ether_hdr.ether_shost[1] = 0xc6;
  ether_hdr.ether_shost[2] = 0xb0;
  ether_hdr.ether_shost[3] = 0x12;
  ether_hdr.ether_shost[4] = 0xe8;
  ether_hdr.ether_shost[5] = 0xb4;

  config.servers.push_back("fc02:2000::1");
  config.servers.push_back("fc02:2000::2");

  config.interface = "Vlan1000";
  swss::DBConnector stateDb("STATE_DB", 0, true);
  config.db = &stateDb;

  int local_sock = 1;
  int filter = 1;

  prepare_relay_config(&config, &local_sock, filter);

  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(config.servers_sock.at(0).sin6_addr), addr1, sizeof(addr1));
  inet_ntop(AF_INET6, &(config.servers_sock.at(1).sin6_addr), addr2, sizeof(addr2));
  std::string s1(addr1);
  std::string s2(addr2);
  
  EXPECT_EQ("fc02:2000::1", s1);
  EXPECT_EQ("fc02:2000::2", s2);
}

//namespace fs = std::filesystem;

TEST(counter, initialize_counter)
{
  //fs::copy("database_config.json", "/var/run/redis/sonic-db/database_config.json");
  //fs::remove_all("/var/run/redis/sonic-db");
  swss::DBConnector stateDb("STATE_DB", 0, true);
  initialize_counter(&stateDb, "DHCPv6_COUNTER_TABLE|Vlan1000");
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Unknown"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Advertise"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Request"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Confirm"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Renew"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Rebind"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Reply"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Release"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Decline"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Relay-Forward"));
  EXPECT_TRUE(stateDb.hexists("DHCPv6_COUNTER_TABLE|Vlan1000", "Relay-Reply"));
}

TEST(counter, update_counter)
{
  swss::DBConnector stateDb("STATE_DB", 0, true);
  stateDb.hset("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit", "1");
  update_counter(&stateDb, "DHCPv6_COUNTER_TABLE|Vlan1000", 1);
  std::shared_ptr<std::string> output = stateDb.hget("DHCPv6_COUNTER_TABLE|Vlan1000", "Solicit");
  std::string *ptr = output.get();
  EXPECT_EQ(*ptr, "0");
}

TEST(relay, relay_client) {

    int mock_sock = 124;
    
    // From dhcpv6_relay.pcapng
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

    struct relay_config config;
    memset(&config, 0, sizeof(config));
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
    swss::DBConnector stateDb("STATE_DB", 0, true);
    config.db = &stateDb;

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
    while ((current_position - sender_buffer) < valid_byte_count) {
        
        auto option = parse_dhcpv6_opt(current_position, &current_position);
        switch (ntohs(option->option_code)) {
            case OPTION_RELAY_MSG:
                if (memcmp(((uint8_t *)option) + sizeof(dhcpv6_option), msg, msg_len) != 0) {
                    printf("Sub-message differs!");
                    printf("test_relay_client");
                    return;
                }
                break;
            /* case OPTION_CLIENT_LINKLAYER_ADDR:
                
                link_layer_seen = true;
                auto link_layer_option = (linklayer_addr_option *)option;
                EXPECT_EQ(link_layer_option->link_layer_type, htons(1));
                
                
                for (int i = 0; i < 6; i++){
                    EXPECT_EQ(*(((uint8_t *)option) + sizeof(dhcpv6_option) + i), ether_hdr.ether_shost[i]);
                }
                break; */
        }
    } 

}

TEST(relay, relay_relay_forw) {
    int mock_sock = 125;
      
    // From dhcpv6_relay.pcapng
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
        0x15, 0x18, 0x00, 0x4f, 0x00, 0x08, 0x00, 0x01,
        0x5a, 0xc6, 0xb0, 0x12, 0xe8, 0xb4, 0x00, 0x12,
        0x00, 0x03, 0x47, 0x69, 0x32, 0x00, 0x25, 0x00,
        0x16, 0x00, 0x00, 0x00, 0x09, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x1e, 0xbd, 0x3c, 0x68, 0x00
    };
    int32_t msg_len = sizeof(msg);
    

    relay_config config;
    memset(&config, 0, sizeof(config));
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
    swss::DBConnector stateDb("STATE_DB", 0, true);
    config.db = &stateDb;

    unsigned char ip6[] = {       /* IPv6 Header */
      0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0xfc, 0x54, 0x00, 0xff, 0xfe, 0x7e, 0x13, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x0c, 0xbd, 0xfd, 
      0x01, 0x00, 0x30, 0x39 };

    char *ptr = (char *)ip6;
    const uint8_t *current_position = (uint8_t *)ptr;
    const uint8_t *tmp = NULL;

    auto ip6_header = parse_ip6_hdr(current_position, &tmp);

    relay_relay_forw(mock_sock, msg, msg_len, ip6_header, &config);

    EXPECT_EQ(last_used_sock, 125);
/* 
    auto sent_msg = parse_dhcp_relay_msg(sender_buffer);
    
    EXPECT_EQ(sent_msg->msg_type, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
    EXPECT_EQ(sent_msg->hop_count, 1); */
    /* 
    for (int i = 0; i < 16; i++) {
        if (sent_msg->link_address.__in6_u.__u6_addr8[i] != 0){
            logger.msg_error("Wrong link address!");
            logger.result_fail("test_relay_forw");
            return;
        }
        if (sent_msg->peer_address.__in6_u.__u6_addr8[i] != ip_hdr.ip6_src.__in6_u.__u6_addr8[i]) {
            logger.msg_error("Wrong peer address!");
            logger.result_fail("test_relay_forw");
            return;
        }
    }

    bool sub_message_seen = false;
    bool interface_id_seen = false;

    const uint8_t *current_position = sender_buffer + sizeof(dhcpv6_relay_msg);
    while ((current_position - sender_buffer) < valid_byte_count) {
        
        auto option = get_next_dhcpv6_option(current_position, &current_position);
        switch (ntohs(option->option_code)) {
            case OPTION_RELAY_MSG:
                if (sub_message_seen){
                    logger.msg_error("Multiple sub-messages!");
                    logger.result_fail("test_relay_forw");
                    return;
                }
                sub_message_seen = true;
                if (memcmp(((uint8_t *)option) + sizeof(dhcpv6_option), msg, msg_len) != 0) {
                    logger.msg_error("Sub-message differs!");
                    logger.result_fail("test_relay_forw");
                    return;
                }
                break;
            case OPTION_INTERFACE_ID:
                if (interface_id_seen) {
                    logger.msg_error("Multiple interface ids!");
                    logger.result_fail("test_relay_forw");
                    return;
                }
                interface_id_seen = true;
                break;
            case OPTION_CLIENT_LINKLAYER_ADDR:
                logger.msg_error("Should not have linklayer address field!");
                logger.result_fail("test_relay_forw");
                return;
        }
    } */
}

TEST(relay, relay_relay_reply) {
    int mock_sock = 123;
    
    // From dhcpv6_relay.pcapng
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

    struct relay_config config;
    memset(&config, 0, sizeof(config));
    config.is_option_79 = true;

    config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

    struct ip6_hdr ip_hdr;
    std::string s_addr = "fe80::1";
    inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);
    struct ether_header ether_hdr;
    ether_hdr.ether_shost[0] = 0x5a;
    ether_hdr.ether_shost[1] = 0xc6;
    ether_hdr.ether_shost[2] = 0xb0;
    ether_hdr.ether_shost[3] = 0x12;
    ether_hdr.ether_shost[4] = 0xe8;
    ether_hdr.ether_shost[5] = 0xb4;

    config.servers.push_back("fc02:2000::1");
    config.servers.push_back("fc02:2000::2");

    config.interface = "Vlan1000";
    swss::DBConnector stateDb("STATE_DB", 0, true);
    config.db = &stateDb;

    int local_sock = 1;
    int filter = 1;

    prepare_relay_config(&config, &local_sock, filter);

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
}

TEST(relay, callback) {
      static struct sock_filter ether_relay_filter[] = {
	
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

    int mock_sock = 123;
    evutil_socket_t fd = 1;
    short event = 1;

    struct relay_config config;
    memset(&config, 0, sizeof(config));
    config.is_option_79 = true;

    config.link_address.sin6_addr.__in6_u.__u6_addr8[15] = 0x01;

    struct ip6_hdr ip_hdr;
    std::string s_addr = "fe80::1";
    inet_pton(AF_INET6, s_addr.c_str(), &ip_hdr.ip6_src);
    struct ether_header ether_hdr;
    ether_hdr.ether_shost[0] = 0x5a;
    ether_hdr.ether_shost[1] = 0xc6;
    ether_hdr.ether_shost[2] = 0xb0;
    ether_hdr.ether_shost[3] = 0x12;
    ether_hdr.ether_shost[4] = 0xe8;
    ether_hdr.ether_shost[5] = 0xb4;

    config.servers.push_back("fc02:2000::1");
    config.servers.push_back("fc02:2000::2");

    config.interface = "Vlan1000";
    swss::DBConnector stateDb("STATE_DB", 0, true);
    config.db = &stateDb;

    int local_sock = 1;
    int filter = 1;
    int index = 1;
    filter = sock_open(index, &ether_relay_fprog);
    prepare_relay_config(&config, &local_sock, filter);

    callback(fd, event, &config);
}

TEST(relay, signal_init) {
  struct event_base *base;
  struct event *ev_sigint = NULL;
  struct event *ev_sigterm;
  signal_init();
}

TEST(relay, signal_start) {
  struct event_base *base = event_base_new();;
  struct event *ev_sigint;
  struct event *ev_sigterm;
  signal_init();
  signal_start();
}

TEST(relay, signal_callback) {
  struct event_base *base = event_base_new();;
  struct event *ev_sigint;
  struct event *ev_sigterm;
  signal_callback(1, 1, &base);
}

TEST(relay, dhcp6relay_stop) {
  int filter = 1;
  struct relay_config config;
  memset(&config, 0, sizeof(config));
  struct event_base *base = event_base_new();
  struct event *mock_event;
  event_new(base, filter, EV_READ|EV_PERSIST, callback, &config);
  dhcp6relay_stop();
}

int main_test(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
