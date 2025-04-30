#pragma once

#include <arpa/inet.h>
#include <event2/util.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <syslog.h>

#include <map>
#include <string>
#include <vector>

#include "dbconnector.h"
#include "dhcp4_sender.h"
#include "table.h"

#define PACKED __attribute__((packed))

#define RELAY_PORT 67
#define CLIENT_PORT 68
#define HOP_LIMIT 4
#define DHCPv4_OPTION_LIMIT 255
#define RAWSOCKET_RECV_SIZE 1048576
#define CLIENT_IF_PREFIX "Ethernet"
#define BUFFER_SIZE 9200        // TODO: change to dynamic size based on MTU
#define MAX_DHCP_PKT_SIZE 1472  // 1500 - (IP + UDP)headers
#define MAC_ADDR_LEN 6

#define BOOTPREQUEST 1
#define BOOTPREPLY 2
#define BOOTP_HTYPE_ETHERNET 1
#define BOOTP_HLEN_ETHERNET 6
#define BOOTP_FLAGS_BROADCAST 0x8000
#define DHCP_BROADCAST_IPADDR 0xFFFFFFFF

#define DHCP_SUB_OPT_TLV_LENGTH_OFFSET 1
#define DHCP_SUB_OPT_TLV_HEADER_LEN 2

#define lengthof(A) (sizeof(A) / sizeof(A)[0])

extern char vrf_single[IF_NAMESIZE];
extern bool vrf_sock_set;
extern int config_pipe[2];

#define OPTION_RELAY_MSG 82
#define OPTION82_SUBOPT_CIRCUIT_ID 1
#define OPTION82_SUBOPT_REMOTE_ID 2
#define OPTION82_SUBOPT_LINK_SELECTION 5
#define OPTION82_SUBOPT_SERVER_OVERRIDE 11
#define OPTION82_SUBOPT_VIRTUAL_SUBNET 151

#define DHCP_ETHERNET_HDR_LEN 14
#define DHCP_IP_HDR_LEN 20
#define DHCP_UDP_HDR_LEN 8
#define DHCP_UDP_OVERHEAD_LEN (DHCP_ETHERNET_HDR_LEN + DHCP_IP_HDR_LEN + DHCP_UDP_HDR_LEN)
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128
#define DHCP_FIXED_NON_UDP_LEN 236
#define DHCP_FIXED_LEN (DHCP_FIXED_NON_UDP_LEN + DHCP_UDP_OVERHEAD_LEN)
#define DHCP_MTU_MAX 9216
#define DHCP_OPTION_LEN (DHCP_MTU_MAX - DHCP_FIXED_LEN)

#define BATCH_SIZE 64

extern char loopback[IF_NAMESIZE];

struct VrfSocketInfo {
    int sock;
    uint16_t ref_count;
};

/* DHCPv4 message types */
typedef enum {
    DHCPv4_MESSAGE_TYPE_UNKNOWN,
    DHCPv4_MESSAGE_TYPE_DISCOVER,
    DHCPv4_MESSAGE_TYPE_OFFER,
    DHCPv4_MESSAGE_TYPE_REQUEST,
    DHCPv4_MESSAGE_TYPE_DECLINE,
    DHCPv4_MESSAGE_TYPE_ACK,
    DHCPv4_MESSAGE_TYPE_NAK,
    DHCPv4_MESSAGE_TYPE_RELEASE,
    DHCPv4_MESSAGE_TYPE_INFORM,
    DHCPv4_MESSAGE_TYPE_MALFORMED,
    DHCPv4_MESSAGE_TYPE_DROP,

    DHCPv4_MESSAGE_TYPE_COUNT
} dhcp_message_type_t;

struct relay_config {
    /* Client facing socket, use to send packet to client */
    int client_sock;
    /* Server facing socket, use to send packet to server */
    int vrf_sock;
    int lo_sock;
    int filter;
    sockaddr_in link_address;
    sockaddr_in link_address_netmask;
    sockaddr_in src_intf_sel_addr;
    uint32_t link_ifindex;
    uint8_t host_mac_addr[MAC_ADDR_LEN];
    std::shared_ptr<swss::DBConnector> state_db;
    std::string vlan;
    std::string phy_interface;
    std::string vrf;  // This is server VRF.
    std::string source_interface;
    std::string link_selection_opt;
    std::string server_id_override_opt;
    std::string vrf_selection_opt;
    std::string agent_relay_mode;
    std::string hostname;
    std::vector<std::string> servers;
    std::vector<sockaddr_in> servers_sock;
    bool is_interface_id;
    bool is_add;
    std::shared_ptr<swss::DBConnector> config_db;
};

typedef enum {
    DHCPv4_RELAY_CONFIG_UNKNOWN,
    DHCPv4_RELAY_CONFIG_UPDATE,
    DHCPv4_RELAY_INTERFACE_UPDATE,
    DHCPv4_RELAY_METADATA_UPDATE
} event_type;

struct event_config {
    event_type type;
    void *msg;
};

/**
 * @code                sock_open(const struct sock_fprog *fprog);
 *
 * @brief               prepare L2 socket to attach to "udp and port 67" filter
 *
 * @param fprog         bpf filter "udp and port 67"
 *
 * @return              socket descriptor
 */
int sock_open(const struct sock_fprog *fprog);

/**
 * @code                prepare_vlan_sockets(relay_config &config);
 *
 * @brief               prepare vlan L3 socket for sending
 *
 * @return              int
 */
int prepare_vlan_sockets(relay_config &config);

/**
 * @code                prepare_vrf_sockets(relay_config &config);
 *
 * @brief               prepare vrf L3 socket for sending
 *
 * @return              int
 */
int prepare_vrf_sockets(relay_config &config);

/**
 * @code                        prepare_relay_interface_config(relay_config &interface_config);
 *
 * @brief                       prepare for specified relay interface config
 *
 * @param interface_config      pointer to relay config to be prepared
 *
 * @return                      none
 */
void prepare_relay_interface_config(relay_config &interface_config);

/**
 * @code                        prepare_relay_server_config(relay_config &interface_config);
 *
 * @brief                       prepare for specified relay server and link address
 *
 * @param interface_config      pointer to relay config to be prepared
 *
 * @return                      none
 */
void prepare_relay_server_config(relay_config &interface_config);

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
 * @brief initialize DHCPv4 Relay libevent signals
 */
int signal_init();

/**
 * @code signal_start();
 *
 * @brief start DHCPv4 Relay libevent base and add signals
 */
int signal_start();

/**
 * @code dhcp4relay_stop();
 *
 * @brief stop DHCPv4 Relay libevent loop upon signal
 */
void dhcp4relay_stop();

/**
 * @code signal_callback(fd, event, arg);
 *
 * @brief signal handler for dhcp4relay. Initiate shutdown when signal is caught
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

/* Helper functions */

/**
 * @code                std::string to_string(uint64_t count);
 *
 * @brief               convert uint64_t to string
 *
 * @param count         count of messages in counter
 *
 * @return              count in string
 */
std::string to_string(uint64_t count);

/**
 * @code                update_vlan_mapping(std::string vlan, bool is_add);
 *
 * @brief               build vlan member interface to vlan mapping table
 *
 * @param vlan          vlan name string
 * @param is_add        add or delete entry
 *
 * @return              none
 */
void update_vlan_mapping(std::string vlan, bool is_add);

/**
 * @code                pkt_in_callback(evutil_socket_t fd, short event, void *arg);
 *
 * @brief               callback for libevent that is called everytime data is received at the filter socket
 *                      this is expected to receive both server and client sent DHCP packets
 *
 * @param fd            filter socket
 * @param event         libevent triggered event
 * @param arg           callback argument provided by user
 *
 * @return              none
 */
void pkt_in_callback(evutil_socket_t fd, short event, void *arg);
bool string_to_mac_addr(const std::string &mac_str, std::array<uint8_t, 6> &mac_addr);
void config_event_callback(evutil_socket_t fd, short event, void *arg);
uint8_t *decode_tlv(const uint8_t *buf, uint8_t t, uint8_t &l, uint32_t options_total_size);
uint8_t encode_tlv(uint8_t *buf, uint8_t t, uint8_t l, uint8_t *v);
