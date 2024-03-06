#pragma once

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <string>
#include <vector>
#include <map>
#include <event2/util.h>
#include <syslog.h>
#include "dbconnector.h"
#include "table.h"
#include "sender.h"

#define PACKED __attribute__ ((packed))

#define RELAY_PORT 547
#define CLIENT_PORT 546
#define HOP_LIMIT 8     //HOP_LIMIT reduced from 32 to 8 as stated in RFC8415
#define DHCPv6_OPTION_LIMIT 147  // follow Option Codes in
                                 // http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml
#define RAWSOCKET_RECV_SIZE 1048576 // system allowed max size under /proc/sys/net/core/rmem_max
#define CLIENT_IF_PREFIX "Ethernet"
#define BUFFER_SIZE 9200

#define lengthof(A) (sizeof (A) / sizeof (A)[0])

#define OPTION_RELAY_MSG 9
#define OPTION_INTERFACE_ID 18
#define OPTION_CLIENT_LINKLAYER_ADDR 79

#define BATCH_SIZE 64

extern bool dual_tor_sock;
extern char loopback[IF_NAMESIZE];

/* DHCPv6 message types */
typedef enum
{
    DHCPv6_MESSAGE_TYPE_UNKNOWN = 0,
    DHCPv6_MESSAGE_TYPE_SOLICIT = 1,
    DHCPv6_MESSAGE_TYPE_ADVERTISE = 2,
    DHCPv6_MESSAGE_TYPE_REQUEST = 3,
    DHCPv6_MESSAGE_TYPE_CONFIRM  = 4,
    DHCPv6_MESSAGE_TYPE_RENEW  = 5,
    DHCPv6_MESSAGE_TYPE_REBIND = 6,
    DHCPv6_MESSAGE_TYPE_REPLY = 7,
    DHCPv6_MESSAGE_TYPE_RELEASE = 8,
    DHCPv6_MESSAGE_TYPE_DECLINE = 9,
    DHCPv6_MESSAGE_TYPE_RECONFIGURE = 10,
    DHCPv6_MESSAGE_TYPE_INFORMATION_REQUEST = 11,
    DHCPv6_MESSAGE_TYPE_RELAY_FORW = 12,
    DHCPv6_MESSAGE_TYPE_RELAY_REPL = 13,
    DHCPv6_MESSAGE_TYPE_MALFORMED = 14,

    DHCPv6_MESSAGE_TYPE_COUNT
} dhcp_message_type_t;

struct relay_config {
    int gua_sock; 
    int lla_sock;
    int lo_sock;
    int filter;
    sockaddr_in6 link_address;
    std::shared_ptr<swss::DBConnector> state_db;
    std::string interface;
    std::string mux_key;
    std::vector<std::string> servers;
    std::vector<sockaddr_in6> servers_sock;
    bool is_option_79;
    bool is_interface_id;
    std::shared_ptr<swss::Table> mux_table;
    std::shared_ptr<swss::DBConnector> config_db;
};

/* DHCPv6 messages and options */

struct PACKED dhcpv6_msg {
    uint8_t msg_type;
    uint8_t xid[3];
};

struct PACKED dhcpv6_relay_msg {
    uint8_t msg_type;
    uint8_t hop_count;
    struct in6_addr link_address;
    struct in6_addr peer_address;
};

struct PACKED dhcpv6_option {
    uint16_t option_code;
    uint16_t option_length;
};

struct PACKED option_linklayer_addr  {
    uint16_t link_layer_type;
    uint8_t link_layer_addr[6];
};

struct PACKED option_interface_id  {
    in6_addr interface_id;  // to accomodate dual-tor, this opaque value is set to carry relay interface's global ipv6 address
};

typedef uint16_t OptionCode;

// DHCPv6 Options Class Definition 
class Options {
public:
    bool Add(OptionCode key, const uint8_t *value, uint16_t len);
    bool Delete(OptionCode key);
    std::vector<uint8_t> Get(OptionCode key);
    std::vector<uint8_t> *MarshalBinary();
    bool UnmarshalBinary(const uint8_t *packet, uint16_t len);

private:
    std::map<OptionCode, std::vector<uint8_t>> m_options;
    std::vector<uint8_t> m_list;
};

// DHCPv6 Relay Message Class Definition
class RelayMsg: public Options {
public:
    RelayMsg() {
        m_buffer = nullptr;
    };
    uint8_t *MarshalBinary(uint16_t &len);
    bool UnmarshalBinary(const uint8_t* packet, uint16_t len);

public:
    dhcpv6_relay_msg m_msg_hdr;
    Options m_option_list;

private:
    std::unique_ptr<uint8_t[]> m_buffer;
};

// DHCPv6 Raw Message Class Definition
class DHCPv6Msg: public Options {
public:
    DHCPv6Msg() {
        m_buffer = nullptr;
    };

    uint8_t *MarshalBinary(uint16_t &len);
    bool UnmarshalBinary(const uint8_t *packet, uint16_t len);

public:
    dhcpv6_msg m_msg_hdr;
    Options m_option_list;

private:
    std::unique_ptr<uint8_t[]> m_buffer;
};

/**
 * @code                sock_open(const struct sock_fprog *fprog);
 *
 * @brief               prepare L2 socket to attach to "udp and port 547" filter 
 *
 * @param fprog         bpf filter "udp and port 547"
 *
 * @return              socket descriptor
 */
int sock_open(const struct sock_fprog *fprog);

/**
 * @code                prepare_lo_socket(const char *lo);
 * 
 * @brief               prepare loopback interface socket for dual tor senario
 *
 * @param lo            loopback interface name
 *
 * @return              int
 */
int prepare_lo_socket(const char *lo);

/**
 * @code                prepare_vlan_sockets(int &gua_sock, int &lla_sock, relay_config &config);
 * 
 * @brief               prepare vlan L3 socket for sending
 *
 * @param gua_sock      socket binded to global address for relaying client message to server and listening for server message
 * @param lla_sock      socket binded to link_local address for relaying server message to client
 *
 * @return              int
 */
int prepare_vlan_sockets(int &gua_sock, int &lla_sock, relay_config &config);

/**
 * @code                        prepare_relay_config(relay_config &interface_config, int gua_sock, int filter);
 * 
 * @brief                       prepare for specified relay interface config: server and link address
 *
 * @param interface_config      pointer to relay config to be prepared
 * @param gua_sock              L3 socket used for relaying messages
 * @param filter                socket attached with filter
 *
 * @return                      none
 */
void prepare_relay_config(relay_config &interface_config, int gua_sock, int filter);

/**
 * @code                 relay_client(const uint8_t *msg, uint16_t len, ip6_hdr *ip_hdr, const ether_header *ether_hdr, relay_config *config);
 * 
 * @brief                construct relay-forward message
 *
 * @param msg            pointer to dhcpv6 message header position
 * @param len            size of data received
 * @param ip_hdr         pointer to IPv6 header
 * @param ether_hdr      pointer to Ethernet header
 * @param config         pointer to the relay interface config
 *
 * @return none
 */
void relay_client(const uint8_t *msg, uint16_t len, const ip6_hdr *ip_hdr, const ether_header *ether_hdr, relay_config *config);

/**
 * @code                 relay_relay_forw(const uint8_t *msg, int32_t len, const ip6_hdr *ip_hdr, relay_config *config)
 *
 * @brief                construct a relay-forward message encapsulated relay-forward message
 *
 * @param msg            pointer to dhcpv6 message header position
 * @param len            size of data received
 * @param ip_hdr         pointer to IPv6 header
 * @param config         pointer to the relay interface config
 *
 * @return none
 */
void relay_relay_forw(const uint8_t *msg, int32_t len, const ip6_hdr *ip_hdr, relay_config *config);

/**
 * @code                relay_relay_reply(const uint8_t *msg, int32_t len, relay_config *configs);
 * 
 * @brief               relay and unwrap a relay-reply message
 *
 * @param msg           pointer to dhcpv6 message header position
 * @param len           size of data received
 * @param config        relay interface config
 *
 * @return              none
 */
void relay_relay_reply(const uint8_t *msg, int32_t len, relay_config *configs);

/**
 * @code                struct relay_config *
 *                      get_relay_int_from_relay_msg(const uint8_t *msg, int32_t len,
 *                                                   std::unordered_map<std::string, relay_config> *vlans)
 * 
 * @brief               get relay interface info from relay message
 *
 * @param addr          ipv6 address
 *
 * @return              bool
 */
struct relay_config *
get_relay_int_from_relay_msg(const uint8_t *msg, int32_t len, std::unordered_map<std::string, relay_config> *vlans);

/**
 * @code                void server_callback_dualtor(evutil_socket_t fd, short event, void *arg);
 * 
 * @brief               callback for libevent that is called everytime data is received at the loopback socket
 *
 * @param fd            loopback socket
 * @param event         libevent triggered event  
 * @param arg           callback argument provided by user
 *
 * @return              none
 */
void server_callback_dualtor(evutil_socket_t fd, short event, void *arg);

/**
 * @code                loop_relay(std::unordered_map<std::string, relay_config> &vlans);
 * 
 * @brief               main loop: configure sockets, create libevent base, start server listener thread
 *  
 * @param vlans         list of vlans retrieved from config_db
 * @param state_db      state_db connector
 */
void loop_relay(std::unordered_map<std::string, relay_config> &vlans);

/**
 * @code signal_init();
 *
 * @brief initialize DHCPv6 Relay libevent signals
 */
int signal_init();

/**
 * @code signal_start();
 *
 * @brief start DHCPv6 Relay libevent base and add signals
 */
int signal_start();

/**
 * @code dhcp6relay_stop();
 *
 * @brief stop DHCPv6 Relay libevent loop upon signal
 */
void dhcp6relay_stop();

/**
 * @code signal_callback(fd, event, arg);
 *
 * @brief signal handler for dhcp6relay. Initiate shutdown when signal is caught
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer to libevent base
 *
 * @return none
 */
void signal_callback(evutil_socket_t fd, short event, void *arg);

/**
 * @code shutdown();
 *
 * @brief free signals and terminate threads
 */
void shutdown_relay();

/**
 * @code                void initialize_counter(std::shared_ptr<swss::Table> state_db, std::string &ifname);
 *
 * @brief               initialize the counter for interface
 *
 * @param std::shared_ptr<swss::Table> state_db     state_db connector
 * @param ifname        interface name
 * 
 * @return              none
 */
void initialize_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname);

/**
 * @code                void increase_counter(shared_ptr<swss::DBConnector>, std::string ifname, uint8_t msg_type);
 *
 * @brief               increase the counter in state_db with count of each DHCPv6 message type
 *
 * @param shared_ptr<swss::DBConnector> state_db     state_db connector
 * @param ifname        interface name
 * @param msg_type      dhcpv6 message type to be increased in counter
 * 
 * @return              none
 */
void increase_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname, uint8_t msg_type);

/* Helper functions */

/**
 * @code                std::string toString(uint64_t count);
 *
 * @brief               convert uint64_t to string
 *
 * @param count         count of messages in counter
 * 
 * @return              count in string
 */
std::string toString(uint64_t count);

/**
 * @code                const struct ether_header *parse_ether_frame(const uint8_t *buffer, const uint8_t **out_end);
 *
 * @brief               parse through ethernet frame
 *
 * @param *buffer       message buffer
 * @param **out_end     pointer
 * 
 * @return ether_header end of ethernet header position
 */
const struct ether_header *parse_ether_frame(const uint8_t *buffer, const uint8_t **out_end);

/**
 * @code                const struct ip6_hdr *parse_ip6_hdr(const uint8_t *buffer, const uint8_t **out_end);
 *
 * @brief               parse through ipv6 header
 *
 * @param *buffer       message buffer
 * @param **out_end     pointer
 * 
 * @return ip6_hdr      end of ipv6 header position
 */
const struct ip6_hdr *parse_ip6_hdr(const uint8_t *buffer, const uint8_t **out_end);

/**
 * @code                const struct udphdr *parse_udp(const uint8_t *buffer, const uint8_t **out_end);
 *
 * @brief               parse through udp header
 *
 * @param *buffer       message buffer
 * @param **out_end     pointer
 * 
 * @return udphdr      end of udp header position
 */
const struct udphdr *parse_udp(const uint8_t *buffer, const uint8_t **out_end);

/**
 * @code                const struct dhcpv6_msg *parse_dhcpv6_hdr(const uint8_t *buffer);
 *
 * @brief               parse through dhcpv6 header
 *
 * @param *buffer       message buffer
 * @param **out_end     pointer
 * 
 * @return dhcpv6_msg   end of dhcpv6 header position
 */
const struct dhcpv6_msg *parse_dhcpv6_hdr(const uint8_t *buffer);

/**
 * @code                const struct dhcpv6_relay_msg *parse_dhcpv6_relay(const uint8_t *buffer);
 *
 * @brief               parse through dhcpv6 relay message
 *
 * @param *buffer       message buffer
 * @param **out_end     pointer
 * 
 * @return dhcpv6_relay_msg   start of dhcpv6 relay message or end of dhcpv6 message type position
 */
const struct dhcpv6_relay_msg *parse_dhcpv6_relay(const uint8_t *buffer);

/**
 * @code                update_vlan_mapping(std::string vlan, std::shared_ptr<swss::DBConnector> cfgdb);
 *
 * @brief               build vlan member interface to vlan mapping table 
 *
 * @param vlan          vlan name string
 * @param cfgdb         config db connection
 *
 * @return              none
 */
void update_vlan_mapping(std::string vlan, std::shared_ptr<swss::DBConnector> cfgdb);

/**
 * @code                client_callback(evutil_socket_t fd, short event, void *arg);
 *
 * @brief               callback for libevent that is called everytime data is received at the filter socket
 *
 * @param fd            filter socket
 * @param event         libevent triggered event
 * @param arg           callback argument provided by user
 *
 * @return              none
 */
void client_callback(evutil_socket_t fd, short event, void *arg);

/**
 * @code                client_packet_handler(uint8_t *buffer, ssize_t length, struct relay_config *config, std::string &ifname);
 *
 * @brief               dhcpv6 client packet handler
 *
 * @param buffer        packet buffer
 * @param length        packet length
 * @param config        vlan related relay config
 * @param ifname        vlan member interface name
 *
 * @return              none
 */
void client_packet_handler(uint8_t *buffer, ssize_t length, struct relay_config *config, std::string &ifname);

/**
 * @code                void server_callback(evutil_socket_t fd, short event, void *arg);
 * 
 * @brief               callback for libevent that is called everytime data is received at the server socket
 *
 * @param fd            filter socket
 * @param event         libevent triggered event  
 * @param arg           callback argument provided by user
 *
 * @return              none
 */
void server_callback(evutil_socket_t fd, short event, void *arg);

