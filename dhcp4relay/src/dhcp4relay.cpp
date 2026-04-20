#include <errno.h>
#include <event.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <fcntl.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <signal.h>
#include <unistd.h>
#include <fstream>

#include "configdb.h"
#include "dhcp4_sender.h"
#include "dhcp4relay_mgr.h"
#include "dhcp4relay_stats.h"
#include "sonicv2connector.h"

struct event_base *base;
struct event *ev_sigint;
struct event *ev_sigterm;
extern bool feature_dhcp_server_enabled;
extern std::string global_dhcp_server_ip;
extern metadata_config m_config;

static uint8_t client_recv_buffer[BUFFER_SIZE];
int config_pipe[2];

/* DHCPv4 filter */
static struct sock_filter ether_relay_filter[] = {
    /* Make sure this is an IP packet... */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

    /* Make sure it's a UDP packet... */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

    /* Make sure this isn't a fragment... */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
    BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

    /* Get the IP header length... */
    BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

    /* Make sure it's to the right port... */
    BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 1), /* patch */

    /* If we passed all the tests, ask for the whole packet. */
    BPF_STMT(BPF_RET + BPF_K, (u_int)-1),

    /* Otherwise, drop it. */
    BPF_STMT(BPF_RET + BPF_K, 0),
};

const struct sock_fprog ether_relay_fprog = {
    lengthof(ether_relay_filter),
    ether_relay_filter};

/* Physical interface to relay interface mapping */
std::unordered_map<std::string, std::string> interface_map;

/* VRF sock map is created to avoid multiple sockets for same VRF
   We can expect multiple servers on same VRF, we no need to open VRF sockets
   for each VRF instead we can make use of existing VRF socket opened.
   to map that i will maintain a map with VRF against socket of vrf.
   when ever there is a configuration to open a new socket for the VRF
   check in this MAP if exists update relay_config or else update created
   socket against VRF.
*/
/* VRF sock map */
std::unordered_map<std::string, VrfSocketInfo> vrf_sock_map;

/* This map will have relay interface to VRF mapping */
std::unordered_map<std::string, std::string> interface_vrf_map;

/* This map will have interface name to interface alias map */
std::unordered_map<std::string, std::string> phy_interface_alias_map;

/* This map will have circuit ID to interface mapping for reverse lookup */
std::unordered_map<std::string, std::string> circuit_id_interface_map;

/* DHCP Relay Counter Table Instance */
DHCPCounter_table dhcp_cntr_table;

/* DHCP Relay config manager Instance */
DHCPMgr dhcp_mgr;

/* Interfaces list in config DB */
std::vector<std::string> interface_list;

#ifdef UNIT_TEST
using namespace swss;
#endif

std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);

std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);

/**
 * @code                sock_open(const struct sock_fprog *fprog);
 *
 * @brief               prepare socket to receive all DHCP packet
 *
 * @param fprog         bpf filter "udp and port 67"
 *
 * @return              socket descriptor
 */
int sock_open(const struct sock_fprog *fprog) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] socket: Failed to create socket with error %s\n", strerror(errno));
        return -1;
    }

    evutil_make_listen_socket_reuseable(s);
    evutil_make_socket_nonblocking(s);

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = 0  // any interface
    };

    if (bind(s, (struct sockaddr *)&sll, sizeof sll) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] bind: Failed to bind to specified interface, error: %s\n", strerror(errno));
        (void)close(s);
        return -1;
    }
    if (fprog && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, fprog, sizeof *fprog) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] setsockopt: Failed to attach filter, error: %s\n", strerror(errno));
        (void)close(s);
        return -1;
    }

    int optval = 0;
    socklen_t optlen = sizeof(optval);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] getsockopt: Failed to get recv buffer size, error:  %s\n", strerror(errno));
        (void)close(s);
        return -1;
    }

    int optval_new = RAWSOCKET_RECV_SIZE;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval_new, sizeof(optval_new)) == -1) {
        syslog(LOG_WARNING, "[DHCPV4_RELAY] setsockopt: Failed to set recv buffer size to %d, use default value\n", optval_new);
    } else {
        syslog(LOG_INFO, "[DHCPV4_RELAY] setsockopt: change raw socket recv buffer size from %d to %d\n", optval, optval_new);
    }

    optval = 1;
    if (setsockopt(s, SOL_PACKET, PACKET_AUXDATA, &optval, sizeof(optval)) == -1) {
        syslog(LOG_WARNING, "[DHCPV4_RELAY] setsockopt: Failed to set packet AUXDATA \n");
        (void)close(s);
        return -1;
    }

    int ignore_outgoing = 1;
    if (setsockopt(s, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing)) == -1) {
        syslog(LOG_WARNING, "[DHCPV4_RELAY] setsockopt: Failed to ignore outgoing \n");
    } else {
        syslog(LOG_INFO, "[DHCPV4_RELAY] setsockopt: outgoing packet is ignored\n");
    }

    return s;
}

void prepare_relay_server_config(relay_config &interface_config) {
    for (auto server : interface_config.servers) {
        sockaddr_in tmp;
        if (inet_pton(AF_INET, server.c_str(), &tmp.sin_addr) != 1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] inet_pton: Failed to convert IPv4 address\n");
            return;
        }
        tmp.sin_family = AF_INET;
        tmp.sin_port = htons(RELAY_PORT);
        auto it = std::find_if(
            interface_config.servers_sock.begin(),
            interface_config.servers_sock.end(),
            [&tmp](const sockaddr_in &entry) {
                return entry.sin_addr.s_addr == tmp.sin_addr.s_addr;
            }
        );
        /*If server_sock is already present then don't add it.*/
        if (it == interface_config.servers_sock.end()) {
            interface_config.servers_sock.push_back(tmp);
        }
    }
    if (interface_config.servers_sock.size() != interface_config.servers.size()) {
        for (size_t index = 0; index < interface_config.servers_sock.size();) {
            char ip_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &interface_config.servers_sock[index].sin_addr, ip_str, INET_ADDRSTRLEN);

            auto found = std::find(interface_config.servers.begin(),
                                   interface_config.servers.end(),
                                   std::string(ip_str));

            if (found == interface_config.servers.end()) {
                interface_config.servers_sock.erase(interface_config.servers_sock.begin() + index);
            } else {
                ++index;
            }
        }
    }
}

/**
 * @code                        addr_is_primary(const std::string &ifname, const struct in_addr *addr);
 *
 * @brief                       Check if the given IPv4 address is primary on the interface
 *                              by querying ConfigDB. Searches for matching VLAN_INTERFACE
 *                              keys and checks the "secondary" field.
 *
 * @param ifname                interface name (e.g. "Vlan1000")
 * @param addr                  pointer to the IPv4 address to check
 *
 * @return                      true if the address is primary or not found in ConfigDB, false if secondary
 */
bool addr_is_primary(const std::string &ifname, const struct in_addr *addr) {
    // Check VLAN_INTERFACE table first
    auto match_pattern = std::string("*") + CFG_VLAN_INTF_TABLE_NAME + "|" + ifname + "|*";
    auto keys = config_db->keys(match_pattern);

    for (const auto &key : keys) {
        auto last_bar = key.find_last_of('|');
        auto last_slash = key.find_last_of('/');
        if (last_bar == std::string::npos || last_slash == std::string::npos || last_bar >= last_slash) {
            continue;
        }
        auto addr_str = key.substr(last_bar + 1, last_slash - last_bar - 1);
        struct in_addr curr_addr;
        if (inet_pton(AF_INET, addr_str.c_str(), &curr_addr) == 1 && curr_addr.s_addr == addr->s_addr) {
            auto val = config_db->hget(key, "secondary");
            return val == nullptr || *val != "true";
        }
    }

    // If not found in VLAN_INTERFACE, check INTERFACE table for physical ports
    auto match_pattern2 = std::string("*INTERFACE|") + ifname + "|*";
    auto keys2 = config_db->keys(match_pattern2);

    for (const auto &key : keys2) {
        auto last_bar = key.find_last_of('|');
        auto last_slash = key.find_last_of('/');
        if (last_bar == std::string::npos || last_slash == std::string::npos || last_bar >= last_slash) {
            continue;
        }
        auto addr_str = key.substr(last_bar + 1, last_slash - last_bar - 1);
        struct in_addr curr_addr;
        if (inet_pton(AF_INET, addr_str.c_str(), &curr_addr) == 1 && curr_addr.s_addr == addr->s_addr) {
            auto val = config_db->hget(key, "secondary");
            return val == nullptr || *val != "true";
        }
    }

    return true;
}

/**
 * @code                        prepare_relay_interface_config(relay_config &interface_config);
 *
 * @brief                       prepare for specified relay interface config: server and link address
 *
 * @param interface_config      pointer to relay config to be prepared
 *
 * @return                      none
 */
void prepare_relay_interface_config(relay_config &interface_config) {
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in intf_addr;
    sockaddr_in net_mask;
    sockaddr_in src_intf_sel;
    bool intf_name_set = false;
    bool source_intf_sel_opt = false;

    if (getifaddrs(&ifa) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] getifaddrs: Unable to get network interfaces, error: %s\n", strerror(errno));
        return;
    }

    if (m_config.is_dualTor) {
        /* If DualTor is enabled, we set source interface to "Loopback0"
           and link_selection option will be enabled during encoding if is_dualTor is enabled */
        interface_config.source_interface = "Loopback0";
        syslog(LOG_INFO,
               "[DHCPV4_INFO][DualTor] %s: link_selection_opt is enabled and source interface is set to %s\n",
               interface_config.interface.c_str(), interface_config.source_interface.c_str());
    }

    if (interface_config.source_interface.length() > 0) {
        syslog(LOG_INFO, "[DHCPV4_INFO] source interface addr is set to %s\n",
               interface_config.source_interface.c_str());
    } else {
        /* This flag is used to make sure source interface address is copied to config cache
           if source interface selection is not set with interface we set this flag true
           and we wont copy any source interface selection related information
         */
        source_intf_sel_opt = true;
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if (ifa_tmp->ifa_addr && ifa_tmp->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)ifa_tmp->ifa_addr;
            struct sockaddr_in *mask = (struct sockaddr_in *)ifa_tmp->ifa_netmask;
            if (strcmp(ifa_tmp->ifa_name, interface_config.interface.c_str()) == 0) {
                if (addr_is_primary(interface_config.interface, &in->sin_addr)) {
                    intf_addr = *in;
                    net_mask = *mask;
                    intf_name_set = true;
                }
            } else if ((!source_intf_sel_opt) &&
                       (strcmp(ifa_tmp->ifa_name, interface_config.source_interface.c_str()) == 0)) {
                src_intf_sel = *in;
                source_intf_sel_opt = true;
            }
        }
        if (intf_name_set && source_intf_sel_opt) {
            break;
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    freeifaddrs(ifa);

    interface_config.link_address = intf_addr;
    interface_config.link_address_netmask = net_mask;
    interface_config.src_intf_sel_addr = src_intf_sel;
}

int prepare_vrf_sockets(relay_config &config) {
    /* Open a socket per server VRF, check socket is already available for that VRF */
    int vrf_sock = -1;
    auto itr = vrf_sock_map.find(config.vrf.c_str());
    if (itr == vrf_sock_map.end()) {
        /* Vrf sock is not available in map need to create */
        vrf_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (vrf_sock == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] socket: Failed to create client_addr socket vrf %s err = %s\n",
                   config.vrf.c_str(), strerror(errno));
            return -1;
        }

        evutil_make_listen_socket_reuseable(vrf_sock);
        evutil_make_socket_nonblocking(vrf_sock);

        if (config.vrf != "default") {
            if (setsockopt(vrf_sock, SOL_SOCKET, SO_BINDTODEVICE,
                           config.vrf.c_str(), strlen(config.vrf.c_str())) < 0) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] setsockopt: Failed to bind socket to %s VRF err = %s\n",
                       config.vrf.c_str(), strerror(errno));
                close(vrf_sock);
                return -1;
            }
        }

        /* Bind socket with UDP port to DHCP src number */
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(RELAY_PORT);
        bind(vrf_sock, (struct sockaddr*)&addr, sizeof(addr));

        /* Update the map */
        vrf_sock_map[config.vrf] = {vrf_sock, 1};
    }

    if (vrf_sock > 0) {
        config.vrf_sock = vrf_sock;
    } else {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to obtain vrf socket(%s) error:%s \n", config.vrf.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * @code                prepare_interface_sockets(relay_config &config);
 *
 * @brief               prepare interface L3 socket for sending (supports both VLANs and physical ports)
 *
 * @param config        relay configuration containing interface information
 *                      This socket will be used to send DHCP packet to server and client.
 *
 * @return              int (0 on success, -1 on failure)
 */
int prepare_interface_sockets(relay_config &config) {
#ifdef UNIT_TEST
    config.client_sock = 1;
#else
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in client_addr = {0};
    int client_sock = 0;
    if ((client_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] socket: Failed to create client_addr socket on interface %s, error: %s\n",
               config.interface.c_str(), strerror(errno));
        return -1;
    }

    evutil_make_listen_socket_reuseable(client_sock);
    evutil_make_socket_nonblocking(client_sock);

    /* Bind client socket to interface (VLAN or physical port) */
    if (setsockopt(client_sock, SOL_SOCKET, SO_BINDTODEVICE, config.interface.c_str(),
                   strlen(config.interface.c_str())) < 0) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] failed to bind client_sock to interface %s, error: %s\n",
               config.interface.c_str(), strerror(errno));
        close(client_sock);
        return -1;
    }

    int retry = 0;
    bool bind_client_addr = false;
    do {
        if (getifaddrs(&ifa) == -1) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] getifaddrs: Unable to get network interfaces with %s\n", strerror(errno));
        } else {
            ifa_tmp = ifa;
            while (ifa_tmp) {
                if (ifa_tmp->ifa_addr && (ifa_tmp->ifa_addr->sa_family == AF_INET)) {
                    if (strcmp(ifa_tmp->ifa_name, config.interface.c_str()) == 0) {
                        struct sockaddr_in *in = (struct sockaddr_in *)ifa_tmp->ifa_addr;
                        if (addr_is_primary(config.interface, &in->sin_addr)) {
                            bind_client_addr = true;
                            client_addr = *in;
                            client_addr.sin_family = AF_INET;
                            client_addr.sin_port = htons(RELAY_PORT);
                            break;
                        }
                    }
                }
                ifa_tmp = ifa_tmp->ifa_next;
            }
            freeifaddrs(ifa);
        }

        if (bind_client_addr) {
            break;
        }

        syslog(LOG_WARNING, "[DHCPV4_RELAY] Retry #%d to bind to sockets on interface %s\n", ++retry, config.interface.c_str());
        sleep(5);
    } while (retry < 6);

    if ((!bind_client_addr) || (bind(client_sock, (sockaddr *)&client_addr, sizeof(client_addr)) == -1)) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] bind: Failed to bind socket to global ipv4 address on interface %s after %d retries with %s\n",
               config.interface.c_str(), retry, strerror(errno));
        /* TODO: Need to close vrf socket if ref count is zero in all failure case */
        close(client_sock);
        return -1;
    }

    int broadcast_enable = 1;
    if (setsockopt(client_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] setsockopt: Failed to set socket to receive broadcast address, error: %s\n",
               strerror(errno));
        close(client_sock);
        return -1;
    }

    int optval = 1;
    if (setsockopt(client_sock, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval)) < 0) {
        syslog(LOG_ERR,
               "[DHCPV4_RELAY] setsockopt: Failed to set socket option to "
               "get IP PKT information, error: %s\n",
               strerror(errno));
        close(client_sock);
        return -1;
    }

    config.client_sock = client_sock;
#endif
    return 0;
}

uint8_t encode_tlv(uint8_t *buf, uint8_t t, uint8_t l, uint8_t *v) {
    *buf = t;
    *(buf + DHCP_SUB_OPT_TLV_LENGTH_OFFSET) = l;
    memcpy((buf + DHCP_SUB_OPT_TLV_HEADER_LEN), v, l);

    return (l + DHCP_SUB_OPT_TLV_HEADER_LEN);
}

std::string get_mac_address(const std::string &ifname) {
    std::string path = "/sys/class/net/" + ifname + "/address";
    std::ifstream file(path);
    if (!file.is_open()) {
        syslog(LOG_ERR, "Fetching mac address for interface %s", ifname.c_str());
        return "";
    }
    std::string mac;
    std::getline(file, mac);
    return mac;
}

void encode_relay_option(pcpp::DhcpLayer *dhcp_pkt, relay_config *config) {
    uint8_t buf[256] = {0};
    uint8_t buf_offset = 0;
    std::string bm_mac;

    auto vrf = interface_vrf_map[config->interface.c_str()];

    /* Get interface alias */
    std::string intf_alias;
    if (phy_interface_alias_map.find(config->phy_interface) != phy_interface_alias_map.end()) {
        intf_alias = phy_interface_alias_map[config->phy_interface];
    }

    /* Encode circuit ID sub-option */
    /* | 1 | 4 | circuit_id | */
    std::string circuit_id;

    /* Determine Circuit ID based on configured format */
    bool is_routed_port = (config->interface.rfind("Vlan", 0) != 0);
    if (!config->circuit_id_format.empty() && !is_routed_port) {
        if (config->circuit_id_format == "interface_ip") {
            /* Use interface IP address as Circuit ID */
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(config->link_address.sin_addr), ip_str, INET_ADDRSTRLEN);
            circuit_id = std::string(ip_str);
        } else if (config->circuit_id_format == "custom") {
            /* Use custom Circuit ID value */
            circuit_id = config->circuit_id;
        } else {
            /* Default format: hostname:interface_alias:interface */
            if (feature_dhcp_server_enabled) {
                circuit_id = m_config.hostname + ":" + intf_alias;
            } else {
                circuit_id = m_config.hostname + ":" + intf_alias + ":" + config->interface;
            }
        }
    } else {
        /* No format specified, use default format */
        if (feature_dhcp_server_enabled) {
            circuit_id = m_config.hostname + ":" + intf_alias;
        } else {
            circuit_id = m_config.hostname + ":" + intf_alias + ":" + config->interface;
        }
    }

    /* Store Circuit ID to interface mapping for reverse lookup in to_client() */
    circuit_id_interface_map[circuit_id] = config->interface;

    auto offset = encode_tlv(buf, OPTION82_SUBOPT_CIRCUIT_ID, circuit_id.length(),
                             (uint8_t *)circuit_id.c_str());
    buf_offset += offset;

    if (!m_config.midplane_bridge.empty()) {
        bm_mac = get_mac_address(m_config.midplane_bridge);
    }

    /* Encode remote ID sub-option */
    /* | 2 | 6 | my_mac| */
    /* if its SmartSwitch we need to fetch mac of bridge-midplane */
    if ((m_config.is_SmartSwitch) && (!bm_mac.empty())) {
        offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_REMOTE_ID,
                            MAC_ADDR_STR_LEN, (uint8_t *)(bm_mac.c_str()));
        buf_offset += offset;
    } else {
        offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_REMOTE_ID,
                            MAC_ADDR_STR_LEN, (uint8_t *)(m_config.host_mac_addr.c_str()));
        buf_offset += offset;
    }

    /* TODO: this sub-option should be set if source interface selection is enabled */
    /* | 5 | 4 | ipv4 | */
    if (m_config.is_dualTor || config->link_selection_opt == "enable") {
        uint32_t link_sel_ip = ((config->link_address.sin_addr.s_addr) &
                                (config->link_address_netmask.sin_addr.s_addr));
        offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_LINK_SELECTION, sizeof(uint32_t),
                            (uint8_t *)&link_sel_ip);
        buf_offset += offset;
    }

    /* | 11 | 4 | ipv4 | */
    if (config->server_id_override_opt == "enable") {
        offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_SERVER_OVERRIDE, sizeof(uint32_t),
                            (uint8_t *)(&(config->link_address.sin_addr.s_addr)));
        buf_offset += offset;
    }

    /* Encode VSS sub-option 151 if client is not default VRF */
    /* | 151 | vrf_len | 0 | vrf_name | */
    uint8_t vss_buf[32] = {0};
    /* Enable VSS only if client and server are in two different VRF's */
    if ((config->vrf_selection_opt == "enable") && (vrf != "default") &&
        (config->vrf != vrf)) {
        uint8_t zero_encode = 0;
        memcpy(vss_buf, &zero_encode, sizeof(uint8_t));
        memcpy((vss_buf + 1), (uint8_t *)vrf.c_str(), (uint8_t)vrf.length());

        offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_VIRTUAL_SUBNET,
                            (uint8_t)(vrf.length() + 1), vss_buf);
        buf_offset += offset;
    }

    /* We shouldn't append relay information if packet size is exceeding MTU size */
    if ((dhcp_pkt->getHeaderLen() + buf_offset) > MAX_DHCP_PKT_SIZE) {
        syslog(LOG_ERR,
               "[DHCPV4_RELAY] %ld packet size is exceeding allowed size %d"
               " from interface %s",
               (dhcp_pkt->getHeaderLen() + buf_offset),
               MAX_DHCP_PKT_SIZE, config->interface.c_str());
        return;
    }

    dhcp_pkt->addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS,
                                                buf, buf_offset));
    return;
}

/**
 * @code                 void from_client(pcpp::DhcpLayer* dhcp_pkt, relay_config *config)
 *
 * @brief                construct relay-forward message
 *
 * @param dhcp_pkt       DHCP layered packet information.
 * @param config         pointer to the relay interface config
 *
 * @return none
 */
void from_client(pcpp::DhcpLayer *dhcp_pkt, relay_config &config) {
    /* Update giaddr */
    if (!(dhcp_pkt->getDhcpHeader()->gatewayIpAddress)) {
        if (config.source_interface.length() > 0) {
            /* find the IP of the interface and update to giaddr */
            dhcp_pkt->getDhcpHeader()->gatewayIpAddress =
                config.src_intf_sel_addr.sin_addr.s_addr;
        } else {
            dhcp_pkt->getDhcpHeader()->gatewayIpAddress =
                config.link_address.sin_addr.s_addr;
        }
        if ((dhcp_pkt->getDhcpHeader()->magicNumber) &&
            (dhcp_pkt->getDhcpHeader()->magicNumber) == DHCP_MAGIC_NUMBER) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] encode DHCP relay option");
            encode_relay_option(dhcp_pkt, &config);
        }
    } else {
        /* If the relay packet is from another relay, we should act based on
           configuration of agent_relay_mode.
           append - Forward the packet with appending relay agent.
           replace - Delete existing option 82 and add my relay option.
           discard - Discard the incoming packet.
         */
        if (config.agent_relay_mode == "append") {
            encode_relay_option(dhcp_pkt, &config);
        } else if (config.agent_relay_mode == "replace") {
            dhcp_pkt->removeOption(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
            encode_relay_option(dhcp_pkt, &config);
        } else {
            /* By default it will discard packet from relay agent */
            dhcp_cntr_table.increment_counter(config.interface, "TX", DHCPv4_MESSAGE_TYPE_DROP);
            syslog(LOG_INFO, "[DHCPV4_RELAY] agent relay mode is discard, dropping the packet %s",
                   config.interface.c_str());
            return;
        }
    }

    /* Drop the packet if the hop count exceeds the configured maximum. */
    if (dhcp_pkt->getDhcpHeader()->hops >= config.max_hop_count) {
        syslog(LOG_NOTICE, "[DHCPV4_RELAY] Dropping packet: hop count %d exceeds max allowed %d\n",
               dhcp_pkt->getDhcpHeader()->hops, config.max_hop_count);
        // increment drop counter
        dhcp_cntr_table.increment_counter(config.interface, "TX", DHCPv4_MESSAGE_TYPE_DROP);
        return;
    }

    /* Increase the hop count */
    dhcp_pkt->getDhcpHeader()->hops = dhcp_pkt->getDhcpHeader()->hops + 1;
    int sock = config.vrf_sock;
    uint32_t index = 0;

    // Backward compatibility for deployment_id 8. If deployment_id is 8, use client interface IP as source IP
    bool use_intf_ip_as_src_ip = false;
    in_addr src_ip = {0};
    if (m_config.deployment_id == 8) {
        use_intf_ip_as_src_ip = true;
        src_ip.s_addr = config.link_address.sin_addr.s_addr;
    }

    for (auto server : config.servers_sock) {
        if (send_udp(sock, (uint8_t *)dhcp_pkt->getDhcpHeader(), server, dhcp_pkt->getHeaderLen(), src_ip, use_intf_ip_as_src_ip, true)) {
            syslog(LOG_INFO, "[DHCPV4_RELAY] DHCP packet is sent to configured server: %s, interface: %s",
                   config.servers[index].c_str(), config.interface.c_str());
            dhcp_cntr_table.increment_counter(config.interface, "TX", (int)dhcp_pkt->getMessageType());
        } else {
            syslog(LOG_NOTICE, "[DHCPV4_RELAY] DHCP packet sending FAILED for configured server: %s, interface: %s",
                   config.servers[index].c_str(), config.interface.c_str());
            // increment drop counter
            dhcp_cntr_table.increment_counter(config.interface, "TX", DHCPv4_MESSAGE_TYPE_DROP);
        }
        index++;
    }
}

uint8_t *decode_tlv(const uint8_t *buf, uint8_t t, uint8_t &l, uint32_t options_total_size) {
    uint8_t *temp = (uint8_t *)buf;
    uint32_t offset = 0;
    uint8_t len = 0;

    while (temp && ((offset + DHCP_SUB_OPT_TLV_HEADER_LEN) <= options_total_size)) {
        len = *(temp + DHCP_SUB_OPT_TLV_LENGTH_OFFSET);
        if ((offset + DHCP_SUB_OPT_TLV_LENGTH_OFFSET + len) > options_total_size) {
            /* Malformed packet */
            syslog(LOG_ERR, "[DHCPV4_INFO] Failed to decode relay agent sub-option %d"
                       " exceeded total option len %d offset %d sub-option len %d\n",
                       t, options_total_size, offset, len);
            l = 0;
            return NULL;
        }
        if (t == *temp) {
            syslog(LOG_INFO, "[DHCPV4_INFO] Decoding relay agent sub-option %d of len %d\n", t, len);
            l = len;
            return (temp + DHCP_SUB_OPT_TLV_HEADER_LEN);
        }
        offset +=  (len + DHCP_SUB_OPT_TLV_HEADER_LEN);
        temp += (len + DHCP_SUB_OPT_TLV_HEADER_LEN);
    }
    l = 0;
    return NULL;
}

/**
 * @code                void to_client(pcpp::DhcpLayer* dhcp_pkt, std::unordered_map<std::string,
                                        relay_config > *interfaces, std::string src_ip);
 *
 * @brief               API will send DHCP relay message to client.
 *
 * @param dhcp_pkt      DHCP layer class, which will have information of DHCP packet.
 * @param interfaces    Client information including socket to send DHCP packet to client.
 *
 * @return              none
 */
void to_client(pcpp::DhcpLayer *dhcp_pkt, std::unordered_map<std::string, relay_config> *interfaces,
               std::string src_ip) {
    struct ifaddrs *ifa, *ifa_tmp;
    struct sockaddr_in target_addr = {0};
    uint32_t giaddr = dhcp_pkt->getDhcpHeader()->gatewayIpAddress;
    uint32_t broadcast_addr = DHCP_BROADCAST_IPADDR;
    bool pad = false;
    std::unordered_map<std::string, relay_config>::iterator config_itr = interfaces->end();

    if (getifaddrs(&ifa) == -1) {
        syslog(LOG_WARNING, "[DHCPV4_RELAY] getifaddrs: Unable to get network interfaces, error: %s\n", strerror(errno));
        exit(1);
    }

    /* Return if giaddr is empty */
    if (giaddr == 0) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Message received with empty giaddr from server %s\n",
               src_ip.c_str());
        return;
    }

    auto agent_option = dhcp_pkt->getOptionData(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
    auto options_ptr = agent_option.getValue();
    auto agent_option_size = agent_option.getDataSize();

    /* If option 82 is available fetch Vlan information from circuit ID */
    if (options_ptr != NULL) {
        uint8_t circuit_id_len = 0;
        auto circuit_id_ptr = decode_tlv((const uint8_t *)options_ptr, OPTION82_SUBOPT_CIRCUIT_ID,
                circuit_id_len, agent_option_size);
        if (circuit_id_ptr == NULL) {
            syslog(LOG_ERR,
                    "[DHCPV4_RELAY] Circuit id sub-option is missing in relay"
                    " agent option from server %s",
                    src_ip.c_str());
            return;
        }

        std::string circuit_id((const char *)circuit_id_ptr, circuit_id_len);

        std::string relay_interface;

        /* First, try to find interface using the circuit_id_interface_map */
        auto circuit_map_itr = circuit_id_interface_map.find(circuit_id);
        if (circuit_map_itr != circuit_id_interface_map.end()) {
            relay_interface = circuit_map_itr->second;
        } else {
            auto intf_pos = circuit_id.rfind(':');
            if (intf_pos != std::string::npos) {
                relay_interface = circuit_id.substr(intf_pos + 1);
            }
        }

        if (relay_interface.length() > 0) {
            config_itr = interfaces->find(relay_interface);
            if (config_itr == interfaces->end()) {
                syslog(LOG_INFO,
                        "[DHCPV4_RELAY] Interface config not found for the circuit"
                        "id encoded interface  %s\n",
                        relay_interface.c_str());
            }
        }
    }

    /* If we couldnt able to find interface config using circuit ID
       Walk through all the interfaces and match for giaddrs. */
    if (config_itr == interfaces->end()) {
        std::string intf_name;
        ifa_tmp = ifa;
        while (ifa_tmp) {
            if (ifa_tmp->ifa_addr && ifa_tmp->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in *)ifa_tmp->ifa_addr;
                if (in->sin_addr.s_addr == giaddr) {
                    intf_name = ifa_tmp->ifa_name;
                    break;
                }
            }
            ifa_tmp = ifa_tmp->ifa_next;
        }
        freeifaddrs(ifa);

        if (intf_name.length() == 0) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to find interface attached to address %u\n", giaddr);
            return;
        }

        // TODO: Add check if interface is prefix with vlan or else try to get vlan attached to ethernet
        //  find vlan attach using interface map. Relay config is mapped to interface.

        /* Expecting interface is SVI interface (VLAN or physical port) */
        config_itr = interfaces->find(intf_name);
        if (config_itr == interfaces->end()) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Config not found for interface %s\n", intf_name.c_str());
            return;
        }
    } else {
        freeifaddrs(ifa);
    }
    auto config = config_itr->second;

    dhcp_cntr_table.increment_counter(config.interface, "RX", (int)dhcp_pkt->getMessageType());
    /* TODO: Also check it is matching remote ID*/

    memcpy(&target_addr.sin_addr, &broadcast_addr, sizeof(struct in_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(CLIENT_PORT);

    in_addr ip_zero = {0};
    /* TODO: Send unicast message to client if BOOTP flag from client is set to unicast */

    /* Perform padding only when DHCP relay (Option 82) information has been stripped from the packet */
    if(dhcp_pkt->removeOption(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS)) {
        syslog(LOG_NOTICE, "Packet is stripped");
        pad = true;
    }

    if (send_udp(config.client_sock, (uint8_t *)dhcp_pkt->getDhcpHeader(), target_addr, dhcp_pkt->getHeaderLen(), ip_zero, false, pad)) {
        syslog(LOG_INFO, "[DHCPV4_RELAY] dhcp relay message is broadcast to client %s from server %s",
               config.interface.c_str(), src_ip.c_str());
        dhcp_cntr_table.increment_counter(config.interface, "TX", (int)dhcp_pkt->getMessageType());
    }
}

/**
 * @code                update_port_interface_mapping(std::string port, std::string relay_interface, bool is_add);
 *
 * @brief               update port to relay interface mapping and DHCP counter table
 *
 * @param port          physical port name string
 * @param relay_interface relay interface name string (VLAN or physical port)
 * @param is_add        add or delete entry
 *
 * @return              none
 */
void update_port_interface_mapping(std::string port, std::string relay_interface, bool is_add) {
    if (is_add) {
        interface_map[port] = relay_interface;
        dhcp_cntr_table.initialize_interface(relay_interface);
        syslog(LOG_INFO, "[DHCPV4_RELAY] Add <%s, %s> into port interface map\n", port.c_str(), relay_interface.c_str());
    } else {
        interface_map.erase(port);
        dhcp_cntr_table.remove_interface(relay_interface);
        syslog(LOG_INFO, "[DHCPV4_RELAY] Remove <%s, %s> from port interface map\n", port.c_str(), relay_interface.c_str());
    }
}

/**
 * @code                update_interface_mapping(std::string interface_name, bool is_add);
 *
 * @brief               build interface mapping table for both VLANs and physical ports
 *
 * @param interface_name interface name string (VLAN or physical port)
 * @param is_add        add or delete entry
 *
 * @return              none
 */
/**
 * @brief Updates the interface mapping for a given interface (VLAN or physical port).
 *
 * This function retrieves all VLAN members for the specified VLAN from the configuration database
 * and updates the global interface map with the port and interface information. For physical ports,
 * it maps the port to itself (similar to DHCPv6 relay behavior).
 *
 * @param interface_name The interface identifier as a string (VLAN or physical port).
 * @param is_add Determines if its ADD or DELETE operation.
 */
void update_interface_mapping(std::string interface_name, bool is_add) {
#ifdef UNIT_TEST
    std::vector<std::string> keys;
    swss::Table vlan_member_table(config_db.get(), "VLAN_MEMBER");
    vlan_member_table.getKeys(keys);
#else
    auto match_pattern = std::string("VLAN_MEMBER|") + interface_name + std::string("|*");
    auto keys = config_db->keys(match_pattern);
#endif

    if (!keys.empty()) {
        // This is a VLAN interface, map member ports to the VLAN
        for (auto &itr : keys) {
            auto found = itr.find_last_of('|');
            auto port = itr.substr(found + 1);
            update_port_interface_mapping(port, interface_name, is_add);
        }
    } else {
        // This is a physical port, map it to itself
        update_port_interface_mapping(interface_name, interface_name, is_add);
        syslog(LOG_INFO, "[DHCPV4_RELAY] %s <%s, %s> %s interface map (physical port)\n",
               is_add ? "Add" : "Remove", interface_name.c_str(), interface_name.c_str(),
               is_add ? "into" : "from");
    }

    /* get VRF attached to the interface from VLAN_INTERFACE or INTERFACE table */
    if (is_add) {
        std::string value;
        std::shared_ptr<swss::Table> vlan_intf_tbl = std::make_shared<swss::Table>(config_db.get(), CFG_VLAN_INTF_TABLE_NAME);
        vlan_intf_tbl->hget(interface_name, "vrf_name", value);

        // If not found in VLAN_INTERFACE, check INTERFACE table for physical ports
        if (value.size() <= 0) {
            std::shared_ptr<swss::Table> intf_tbl = std::make_shared<swss::Table>(config_db.get(), "INTERFACE");
            intf_tbl->hget(interface_name, "vrf_name", value);
        }

        if (value.size() <= 0) {
            /* use default instance as vrf */
            interface_vrf_map[interface_name] = "default";
        } else {
            interface_vrf_map[interface_name] = value;
        }
    } else {
        interface_vrf_map.erase(interface_name);
    }
}

uint16_t ipv4_checksum_cal(const uint8_t* ipv4_header, size_t header_len) {
    uint8_t header[header_len] = {0};

    memcpy(header, ipv4_header, header_len);
    pcpp::iphdr *header_ptr = (pcpp::iphdr *)header;

    header_ptr->headerChecksum = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < header_len; i += 2) {
        sum += (header[i] << 8) | header[i + 1];
    }
    if (header_len & 1) {
        sum += header[header_len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ((uint16_t)~sum);
}

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
void pkt_in_callback(evutil_socket_t fd, short event, void *arg) {
    auto interfaces = reinterpret_cast<std::unordered_map<std::string, struct relay_config> *>(arg);
    timeval time;
    struct cmsghdr *cmsg = NULL;
    struct tpacket_auxdata *aux = NULL;
    struct sockaddr_ll *sll;
    struct sockaddr_ll addr = {0};
    struct msghdr msg = {0};
    struct iovec iov = {0};
    int pkts_num = 0;
    int vlan_id = 0;
    char interface_name[IF_NAMESIZE];
    char control[1024] = {0};

    iov.iov_base = client_recv_buffer;
    iov.iov_len = BUFFER_SIZE;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    while (pkts_num++ < BATCH_SIZE) {
        auto buffer_sz = recvmsg(fd, &msg, 0);
        if (buffer_sz <= 0) {
            if (errno != EAGAIN) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] recv: Failed to receive data at filter socket: %s\n", strerror(errno));
            }
            return;
        }

        /* Find ingress VLAN */
        sll = (struct sockaddr_ll *)msg.msg_name;
        cmsg = (struct cmsghdr *)msg.msg_control;
        vlan_id = 0;
        if (cmsg != NULL) {
            if ((cmsg->cmsg_level == (int)SOL_PACKET) && (cmsg->cmsg_type == (int)PACKET_AUXDATA)) {
                aux = (struct tpacket_auxdata *)(cmsg->__cmsg_data);
                if (aux != NULL) {
                    vlan_id = (aux->tp_vlan_tci & VLAN_MASK);
                }
            }
        }

        if (if_indextoname(sll->sll_ifindex, interface_name) == NULL) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid input interface index %d\n", sll->sll_ifindex);
            continue;
        }
        std::string intf(interface_name);
        auto itr = std::find(interface_list.begin(), interface_list.end(), intf);
        /* To avoid duplicate packets, we are only processing packets from
           interface in PORT_TABLE and packets from VXLAN interface and docker0 interfaces */
        if ((itr == interface_list.end()) && (intf.rfind("VXLAN", 0) != 0) && (intf.rfind("docker0", 0) != 0)) {
            continue;
        }

        std::string relay_intf_str;
        if (vlan_id == 0) {
            /* vlan_id can be 0 when we receive packet from the server */
            auto relay_intf = interface_map.find(intf);
            if (relay_intf == interface_map.end()) {
                if (intf.find(CLIENT_IF_PREFIX) != std::string::npos) {
                    syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid input interface %s\n", interface_name);
                } else if ((m_config.is_SmartSwitch) && (intf.rfind("dpu", 0) == 0) && !m_config.midplane_bridge.empty()) {
                    // if its SmartSwitch, we need to check for bridge_midplane interface
                    relay_intf_str = m_config.midplane_bridge;
                }
            } else {
                relay_intf_str = relay_intf->second;
            }
        } else {
            relay_intf_str = "Vlan" + std::to_string(vlan_id);
        }

        gettimeofday(&time, nullptr);

        // Construct raw socket.
        pcpp::RawPacket raw_packet(static_cast<const uint8_t *>(client_recv_buffer), buffer_sz, time, false);

        pcpp::Packet raw_pkt(&raw_packet);

        /* Extract packets in each layers */
        pcpp::EthLayer *eth_layer = raw_pkt.getLayerOfType<pcpp::EthLayer>();
        if (eth_layer == nullptr) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid Ethernet packet from interface  %s\n", intf.c_str());
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            continue;
        }

        pcpp::IPv4Layer *ip_layer = raw_pkt.getLayerOfType<pcpp::IPv4Layer>();
        if (ip_layer == nullptr) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid IP packet from interface  %s\n", intf.c_str());
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            continue;
        }

        /* Validate IP checksum is correct */
        pcpp::iphdr* ip_hdr = ip_layer->getIPv4Header();
        auto ipv4_checksum = ipv4_checksum_cal((const uint8_t*)ip_hdr, ip_layer->getHeaderLen());
        if (ip_hdr->headerChecksum != htons(ipv4_checksum)) {
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Checksum failed for IP packet from interface %s\n", intf.c_str());
            continue;
        }

        auto src_ip = ip_layer->getSrcIPv4Address().toString();

        pcpp::UdpLayer *udp_layer = raw_pkt.getLayerOfType<pcpp::UdpLayer>();
        if (udp_layer == nullptr) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid UDP packet from interface  %s\n", intf.c_str());
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            continue;
        }

        /* Validate UDP checksum is correct */
        auto udp_checksum = udp_layer->calculateChecksum(false);
        if (htobe16(udp_checksum) != udp_layer->getUdpHeader()->headerChecksum) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] UDP checksum validation is failing "
                        " packet is from interface %s\n", intf.c_str());
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            continue;
        }

        pcpp::DhcpLayer *dhcp_pkt = raw_pkt.getLayerOfType<pcpp::DhcpLayer>();
        if (dhcp_pkt == nullptr) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid DHCP packet from interface  %s\n", intf.c_str());
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_MALFORMED);
            }
            continue;
        }

        if (dhcp_pkt->getDhcpHeader()->opCode == BOOTPREQUEST) {
            if (relay_intf_str.empty()) {
                continue;
            }

            auto config_itr = interfaces->find(relay_intf_str);
            if (config_itr == interfaces->end()) {
                syslog(LOG_WARNING, "[DHCPV4_RELAY] Config not found for interface %s\n", intf.c_str());
                continue;
            }
            auto config = config_itr->second;
            config_itr->second.phy_interface = intf;

            dhcp_cntr_table.increment_counter(config.interface, "RX", (int)dhcp_pkt->getMessageType());
            from_client(dhcp_pkt, config_itr->second);
        } else if (dhcp_pkt->getDhcpHeader()->opCode == BOOTPREPLY) {
            to_client(dhcp_pkt, interfaces, src_ip);
        } else {
            if (vlan_id != 0 && !relay_intf_str.empty()) {
                dhcp_cntr_table.increment_counter(relay_intf_str, "RX", DHCPv4_MESSAGE_TYPE_UNKNOWN);
            }
            continue;
        }
    }
}

/**
 * @code signal_init();
 *
 * @brief initialize DHCPv6 Relay libevent signals
 */
int signal_init() {
    int rv = -1;
    do {
        ev_sigint = evsignal_new(base, SIGINT, signal_callback, base);
        if (ev_sigint == NULL) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Could not create SIGINT libevent signal\n");
            break;
        }

        ev_sigterm = evsignal_new(base, SIGTERM, signal_callback, base);
        if (ev_sigterm == NULL) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Could not create SIGTERM libevent signal\n");
            break;
        }
        rv = 0;
    } while (0);
    return rv;
}

/**
 * @code signal_start();
 *
 * @brief start DHCPv6 Relay libevent base and add signals
 */
int signal_start() {
    int rv = -1;
    do {
        if (evsignal_add(ev_sigint, NULL) != 0) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Could not add SIGINT libevent signal\n");
            break;
        }

        if (evsignal_add(ev_sigterm, NULL) != 0) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Could not add SIGTERM libevent signal\n");
            break;
        }

        if (event_base_dispatch(base) != 0) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Could not start libevent dispatching loop\n");
        }

        rv = 0;
    } while (0);

    return rv;
}

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
void signal_callback(evutil_socket_t fd, short event, void *arg) {
    syslog(LOG_ALERT, "[DHCPV4_RELAY] Received signal: '%s'\n", strsignal(fd));
    if ((fd == SIGTERM) || (fd == SIGINT)) {
        dhcp4relay_stop();
    }
}

/**
 * @code dhcp4relay_stop();
 *
 * @brief stop DHCPv6 Relay libevent loop upon signal
 */
void dhcp4relay_stop() {
    event_base_loopexit(base, NULL);
}

int handle_server_sock(relay_config &interface_config, std::string new_vrf)
{
    /* Decrement the ref count for old vrf value in the vrf_sock_map and after decrement
     * if the value is zero then close the client socket and delete the entry in the map. */
    if (vrf_sock_map.find(interface_config.vrf) != vrf_sock_map.end()) {
        vrf_sock_map[interface_config.vrf].ref_count--;
        if (vrf_sock_map[interface_config.vrf].ref_count == 0) {
            close(interface_config.vrf_sock);
            vrf_sock_map.erase((interface_config.vrf));
        }
    }

    /*Updating the new vrf value to interfaces structure. */
    interface_config.vrf = new_vrf;
    /* For the new server vrf update case, if the entry exists in the vrf_sock_map then
     * increment the ref count only else create a socket and update the ref count. */
    if (vrf_sock_map.find(new_vrf) != vrf_sock_map.end()) {
        interface_config.vrf_sock = vrf_sock_map[new_vrf.c_str()].sock;
        vrf_sock_map[new_vrf].ref_count++;
    } else {
        if (prepare_vrf_sockets(interface_config) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create vrf listen socket");
            return -1;
        }
    }
    return 0;
}

/**
 * @code                void delete_all_relay_configs(std::unordered_map<std::string, relay_config> *interfaces);
 *
 * @brief               Delete all the existing interface entries in case of dhcp_server is enabled/disabled.
 *
 * @param interfaces    Client information including socket to send DHCP packet to client.
 *
 * @return              none
 */
void delete_all_relay_configs(std::unordered_map<std::string, relay_config> *interfaces) {
   for (auto intf = interfaces->begin(); intf != interfaces->end(); ) {
      if (intf->second.client_sock > 0) {
          close(intf->second.client_sock);
      }
      if (intf->second.vrf_sock > 0) {
          vrf_sock_map[intf->second.vrf].ref_count--;
          if (vrf_sock_map[intf->second.vrf].ref_count == 0) {
              close(intf->second.vrf_sock);
              vrf_sock_map.erase(intf->second.vrf);
          }
       }
       update_interface_mapping(intf->first, false);
       intf = interfaces->erase(intf);
   }
}

void config_event_callback(evutil_socket_t fd, short event, void *arg) {
    std::unordered_map<std::string, relay_config> *interfaces = static_cast<std::unordered_map<std::string, relay_config> *>(arg);
    event_config received_event;
    ssize_t bytes_read = read(fd, &received_event, sizeof(received_event));

    if (bytes_read == sizeof(received_event)) {
	    //Do not update the relay configs if dhcp_server is enabled
        if (((received_event.type == DHCPv4_RELAY_CONFIG_UPDATE) && !feature_dhcp_server_enabled) ||
	   (received_event.type == DHCPv4_SERVER_RELAY_CONFIG_UPDATE))	{
            relay_config *relay_msg = static_cast<relay_config *>(received_event.msg);
            if (relay_msg) {
                syslog(LOG_INFO, "[DHCPV4_RELAY] Processing config update: Interface %s", relay_msg->interface.c_str());

                if (relay_msg->is_add) {
                    if (interfaces->find(relay_msg->interface) == interfaces->end()) {
                        /*If entry not exist then creating the entry with empty structure.*/
                        (*interfaces)[relay_msg->interface] = relay_config{};
                        (*interfaces)[relay_msg->interface].interface = relay_msg->interface;
                        update_interface_mapping(relay_msg->interface, true);
                        if (prepare_interface_sockets((*interfaces)[relay_msg->interface]) == -1) {
                            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create interface listen socket");
                            return;
                        }
                        /* Initially filling the interface IP address. */
                        if (relay_msg->source_interface.empty()) {
                            prepare_relay_interface_config((*interfaces)[relay_msg->interface]);
                        }
                    }

                    if ((*interfaces)[relay_msg->interface].servers != relay_msg->servers) {
                        (*interfaces)[relay_msg->interface].servers = relay_msg->servers;
                        prepare_relay_server_config((*interfaces)[relay_msg->interface]);
                    }

                    /* Compare the existing vrf value and the new DB updated vrf value for vrf modification case. */
                    if ((*interfaces)[relay_msg->interface].vrf != relay_msg->vrf) {
                        if (handle_server_sock((*interfaces)[relay_msg->interface], relay_msg->vrf) < 0) {
                            return;
                        }
                    }
                    if ((*interfaces)[relay_msg->interface].source_interface != relay_msg->source_interface) {
                        (*interfaces)[relay_msg->interface].source_interface = relay_msg->source_interface;
                        prepare_relay_interface_config((*interfaces)[relay_msg->interface]);
                    }

                    (*interfaces)[relay_msg->interface].link_selection_opt = relay_msg->link_selection_opt;
                    (*interfaces)[relay_msg->interface].server_id_override_opt = relay_msg->server_id_override_opt;
                    (*interfaces)[relay_msg->interface].vrf_selection_opt = relay_msg->vrf_selection_opt;
                    (*interfaces)[relay_msg->interface].agent_relay_mode = relay_msg->agent_relay_mode;
                    (*interfaces)[relay_msg->interface].max_hop_count = relay_msg->max_hop_count;
                    (*interfaces)[relay_msg->interface].circuit_id_format = relay_msg->circuit_id_format;
                    (*interfaces)[relay_msg->interface].circuit_id = relay_msg->circuit_id;
                } else {
                    if (interfaces->find(relay_msg->interface) != interfaces->end()) {
                        /* In case of interface deletion, close all the sockets.*/
                        if ((*interfaces)[relay_msg->interface].client_sock > 0) {
                            close((*interfaces)[relay_msg->interface].client_sock);
                        }
                        if ((*interfaces)[relay_msg->interface].vrf_sock > 0) {
                            vrf_sock_map[(*interfaces)[relay_msg->interface].vrf].ref_count--;
                            if (vrf_sock_map[(*interfaces)[relay_msg->interface].vrf].ref_count == 0) {
                                close((*interfaces)[relay_msg->interface].vrf_sock);
                                vrf_sock_map.erase((*interfaces)[relay_msg->interface].vrf);
                            }
                        }
                        interfaces->erase(relay_msg->interface);
                        syslog(LOG_INFO, "[DHCPV4_RELAY] Deleted interface %s from configuration", relay_msg->interface.c_str());
                        update_interface_mapping(relay_msg->interface, false);
                    } else {
                        syslog(LOG_WARNING, "[DHCPV4_RELAY] Attempted to delete non-existent interface %s", relay_msg->interface.c_str());
                    }
                }
                delete relay_msg;
            }
        } else if (received_event.type == DHCPv4_RELAY_INTERFACE_UPDATE) {
            relay_config *relay_msg = static_cast<relay_config *>(received_event.msg);
            if (relay_msg) {
                syslog(LOG_INFO, "[DHCPV4_RELAY] Updating source interface for interface %s", relay_msg->interface.c_str());
                if (relay_msg->is_add) {
                    (*interfaces)[relay_msg->interface].src_intf_sel_addr = relay_msg->src_intf_sel_addr;
                } else {
                    memset(&(*interfaces)[relay_msg->interface].src_intf_sel_addr, 0, sizeof(sockaddr_in));
                }
                delete relay_msg;
            }
        } else if (received_event.type == DHCPv4_RELAY_VLAN_MEMBER_UPDATE) {
               vlan_member_config *msg = static_cast<vlan_member_config *>(received_event.msg);
               if (msg) {
                   syslog(LOG_INFO, "[DHCPV4_RELAY] Updating vlan member for VLAN %s", msg->vlan.c_str());
                   if (interfaces->find(msg->vlan) == interfaces->end()) {
                       delete msg;
                       return;
                   }

                   if ((*interfaces)[msg->vlan].client_sock > 0) {
                       close((*interfaces)[msg->vlan].client_sock);
                   }

                   update_port_interface_mapping(msg->interface, msg->vlan, msg->is_add);
                   if (prepare_interface_sockets((*interfaces)[msg->vlan]) == -1) {
                       syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create interface listen socket");
                       return;
                   }
                   delete msg;
               }
	} else if (received_event.type == DHCPv4_RELAY_VLAN_INTERFACE_UPDATE) {
               vlan_interface_config *msg = static_cast<vlan_interface_config *>(received_event.msg);
               if (msg) {
                   syslog(LOG_INFO, "[DHCPV4_RELAY] Updating vlan interface event for VLAN %s", msg->vlan.c_str());
                   if (interfaces->find(msg->vlan) == interfaces->end()) {
                       delete msg;
                       return;
                   }

                   if (!msg->vrf.empty()) {
                       interface_vrf_map[msg->vlan] = msg->vrf;
                   } else {
                      if ((*interfaces)[msg->vlan].client_sock > 0) {
                          close((*interfaces)[msg->vlan].client_sock);
                      }
                      if (prepare_interface_sockets((*interfaces)[msg->vlan]) == -1) {
                          syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create interface listen socket");
                          return;
                      }
                      prepare_relay_interface_config((*interfaces)[msg->vlan]);
                   }

                   std::string value;
                   std::shared_ptr<swss::Table> dhcp_relay_tbl = std::make_shared<swss::Table>(config_db.get(),
                                                                    "DHCPV4_RELAY");
                   dhcp_relay_tbl->hget((msg->vlan), "server_vrf", value);
                   if ((msg->vrf.empty()) || (value.length() != 0)) {
                       return;
                   }

                   if ((*interfaces)[msg->vlan].vrf != msg->vrf) {
                        if (handle_server_sock((*interfaces)[msg->vlan], msg->vrf) < 0) {
                            return;
                        }
                   }
                   delete msg;
               }
        } else if ((received_event.type == DHCPv4_SERVER_FEATURE_UPDATE) ||
                   (received_event.type == DHCPv4_SERVER_IP_DELETE)) {
                   syslog(LOG_INFO, "[DHCPV4_RELAY]  dhcp_server feature table update or server ip delete event received");
                   delete_all_relay_configs(interfaces);
        } else if (received_event.type == DHCPv4_SERVER_IP_UPDATE) {
                syslog(LOG_INFO, "[DHCPV4_RELAY]  dhcp_server IP update in state DB event received");
                for (auto it = interfaces->begin(); it != interfaces->end(); ++it) {
                     relay_config &config = it->second;
                     config.servers.clear();
                     config.servers_sock.clear();
                     config.servers.push_back(global_dhcp_server_ip);
                     prepare_relay_server_config(config);
                }
        } else if (received_event.type == DHCPv4_RELAY_DUAL_TOR_UPDATE) {
            relay_config *relay_msg = static_cast<relay_config *>(received_event.msg);
            if (relay_msg) {
                if (relay_msg->is_add) {
                    syslog(LOG_INFO,
                       "[DHCPV4_RELAY][DualTor] Adding link-selection and source-interface as Loopback0 for existing interfaces");
                } else {
                    syslog(LOG_INFO,
                       "[DHCPV4_RELAY][DualTor] Deleting/Restoring link-selection and source-interface configs for existing interfaces");
                }

                for (auto& intf : *interfaces) {
                    if (relay_msg->is_add) {
                            prepare_relay_interface_config(intf.second);
                    } else {
                        std::shared_ptr<swss::Table> v4_relay_intf_tbl = std::make_shared<swss::Table>(config_db.get(), "DHCPV4_RELAY");
                        std::string value;

                        // Check for the presence of specific keys
                        v4_relay_intf_tbl->hget(intf.second.interface, "link_selection", value);
                        // Check if "link_selection" is present
                        if (value.length() > 0) {
                            // Fetch the value of "link_selection" from the database
                            intf.second.link_selection_opt = value;
                        } else {
                            // link_selection key not found in DB, clear the value
                            intf.second.link_selection_opt.clear();
                        }

                        v4_relay_intf_tbl->hget(intf.second.interface, "source_interface", value);
                        // Check if "source_interface" is present
                        if (value.length() > 0) {
                            // Fetch the value of "source_interface" from the database
                            intf.second.source_interface = value;
                        } else {
                            // source_interface key not found in DB, clear the value
                            intf.second.source_interface.clear();
                        }
                        prepare_relay_interface_config(intf.second);
                    }
                }
                delete relay_msg;
            }
	} else if (received_event.type == DHCPv4_RELAY_PORT_UPDATE) {
               port_config *port_msg = static_cast<port_config *>(received_event.msg);
               if (port_msg) {
                   syslog(LOG_INFO, "[DHCPV4_RELAY] Updating interface %s event", port_msg->phy_interface.c_str());
                    if (port_msg->is_add) {
                       if (std::find(interface_list.begin(), interface_list.end(), port_msg->phy_interface) == interface_list.end()) {
                           interface_list.push_back(port_msg->phy_interface);
                       }
                       phy_interface_alias_map[port_msg->phy_interface] = port_msg->alias;
                   } else {
                       auto it = std::find(interface_list.begin(), interface_list.end(), port_msg->phy_interface);
                       if (it != interface_list.end()) {
                           interface_list.erase(it);
                       }
                       phy_interface_alias_map.erase(port_msg->phy_interface);
                   }
                   delete port_msg;
               }
        }
    } else {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to read config update: expected %lu bytes, got %zd bytes", sizeof(received_event), bytes_read);
    }
}

/**
 * @code                loop_relay(std::unordered_map<relay_config> &interfaces);
 *
 * @brief               main loop: configure sockets, create libevent base, start server listener thread
 *
 * @param interfaces    list of interfaces retrieved from config_db
 */

/**
 * @brief Main loop for the DHCP relay functionality.
 *
 * This function sets up the necessary event base and socket listeners for
 * handling DHCP relay operations. It initializes connections to the state
 * and configuration databases, sets up event listeners for client and server
 * sockets, and prepares interface-specific configurations.
 *
 * @param interfaces A reference to an unordered map containing interface configurations.
 *
 */
void loop_relay(std::unordered_map<std::string, relay_config> &interfaces) {
    base = event_base_new();
    if (base == NULL) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] libevent: Failed to create event base\n");
        exit(EXIT_FAILURE);
    }

    /* Keep a list of physical interface available in config DB*/
    auto match_pattern = std::string("PORT|*");
    auto keys = config_db->keys(match_pattern);

    for (auto &itr : keys) {
        auto found = itr.find_last_of('|');
        auto interface = itr.substr(found + 1);
        interface_list.push_back(interface);
    }

    // Create the pipe for inter-thread communication
    if (pipe(config_pipe) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create config update pipe");
        exit(EXIT_FAILURE);
    }

    // Set the read-end of the pipe to non-blocking mode
    fcntl(config_pipe[0], F_SETFL, O_NONBLOCK);

    // Add the pipe to libevent for async config updates
    struct event *config_event = event_new(base, config_pipe[0], EV_READ | EV_PERSIST,
                                           config_event_callback, reinterpret_cast<void *>(&interfaces));
    if (!config_event) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create event for config pipe");
        exit(EXIT_FAILURE);
    }

    event_add(config_event, NULL);
    syslog(LOG_INFO, "[DHCPV4_RELAY] Added event listener for config updates");

    /* Open a socket with dhcp port, protocol filter */
    auto filter = sock_open(&ether_relay_fprog);
    if (filter != -1) {
        /* Register to the callbck func when there is new packet to the socket from client */
        auto event = event_new(base, filter, EV_READ | EV_PERSIST, pkt_in_callback,
                               reinterpret_cast<void *>(&interfaces));
        if (event == NULL) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] libevent: Failed to create client listen event\n");
            exit(EXIT_FAILURE);
        }
        event_add(event, NULL);
        syslog(LOG_INFO, "[DHCPV4_RELAY] libevent: Add client listen socket event\n");
    } else {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create client listen socket");
        exit(EXIT_FAILURE);
    }

    // Start thread for periodic counters updates to DB
    dhcp_cntr_table.start_db_updates();

    // Start thread for listening of config DB updates
    dhcp_mgr.initialize_config_listener();

    if (signal_init() == 0 && signal_start() == 0) {
        shutdown_relay();
        if (filter != -1) {
            close(filter);
        }
    }
}

/**
 * @code shutdown_relay();
 *
 * @brief free signals and terminate threads
 */
void shutdown_relay() {
    event_del(ev_sigint);
    event_del(ev_sigterm);
    event_free(ev_sigint);
    event_free(ev_sigterm);
    event_base_free(base);
}
