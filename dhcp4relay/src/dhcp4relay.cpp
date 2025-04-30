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

#include <sstream>

#include "configdb.h"
#include "dhcp4_sender.h"
#include "dhcp4relay_mgr.h"
#include "dhcp4relay_stats.h"
#include "sonicv2connector.h"

struct event_base *base;
struct event *ev_sigint;
struct event *ev_sigterm;
static std::string vlan_member = "VLAN_MEMBER|";
static std::string counter_table = "DHCPv4_COUNTER_TABLE|";

static uint8_t client_recv_buffer[BUFFER_SIZE];
int config_pipe[2];

/* DHCPv4 filter */
/* sudo tcpdump -dd "inbound and ip dst 255.255.255.255 && udp dst port 67" */

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

/* interface to vlan mapping */
std::unordered_map<std::string, std::string> vlan_map;

/* VRF sock map is created to avoid multiple sockets for same VRF
   We can expect multiple servers on same VRF, we no need to open VRF sockets
   for each VRF instead we can make use of existing VRF socket opened.
   to map that i will maintain a map with VRF againist socket of vrf.
   when ever there is a configuration to open a new socket for the VRF
   check in this MAP if exists update relay_config or else update created
   socket against VRF.
*/
/* VRF sock map */
std::unordered_map<std::string, VrfSocketInfo> vrf_sock_map;

/* This map will have client vlan to client VRF mapping */
std::unordered_map<std::string, std::string> vlan_vrf_map;

/* This map will have interface name to interface alias map */
std::unordered_map<std::string, std::string> phy_interface_alias_map;

/* DHCP Relay Counter Table Instance */
DHCPCounter_table dhcp_cntr_table;

/*DHCP Relay config manager Instance */
DHCPMgr dhcp_mgr;

#ifdef UNIT_TEST
using namespace swss;
#endif

std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);

std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector>("STATE_DB", 0);
/**
 * @code                std::string to_string(uint64_t count);
 *
 * @brief               convert uint16_t to string
 *
 * @param count         count of messages in counter
 *
 * @return              count in string
 */
std::string to_string(uint64_t count) {
    std::stringstream ss;
    ss << count;
    std::string count_value = ss.str();
    return count_value;
}

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
        interface_config.servers_sock.push_back(tmp);
    }
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
            if (strcmp(ifa_tmp->ifa_name, interface_config.vlan.c_str()) == 0) {
                intf_addr = *in;
                net_mask = *mask;
                intf_name_set = true;
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

        /* Default instance binding to the socket will fail, in default instance case will not bind the socket */
        if (config.vrf != "default") {
            if (setsockopt(vrf_sock, SOL_SOCKET, SO_BINDTODEVICE,
                           config.vrf.c_str(), strlen(config.vrf.c_str())) < 0) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] setsockopt: Failed to bind socket to %s VRF err = %s\n",
                       config.vrf.c_str(), strerror(errno));
                close(vrf_sock);
                return -1;
            }
        }

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
 * @code                prepare_vlan_sockets(int &client_sock, relay_config &config);
 *
 * @brief               prepare vlan L3 socket for sending
 *
 * @param client_sock      socket binded to ip address of vlan interface on which server is configured.
 *                      This socket will be used to send DHCP packet to server and client.
 *
 * @return              int
 */
int prepare_vlan_sockets(relay_config &config) {
#ifdef UNIT_TEST
    config.client_sock = 1;
    config.lo_sock = 1;
#else
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in client_addr = {0};
    int lo_sock = -1, client_sock = 0;
    if ((client_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] socket: Failed to create client_addr socket on interface %s, error: %s\n",
               config.vlan.c_str(), strerror(errno));
        return -1;
    }

    evutil_make_listen_socket_reuseable(client_sock);
    evutil_make_socket_nonblocking(client_sock);

    /* Bind client socket to vlan interface */
    if (setsockopt(client_sock, SOL_SOCKET, SO_BINDTODEVICE, config.vlan.c_str(),
                   strlen(config.vlan.c_str())) < 0) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] failed to bind client_sock to vlan %s, error: %s\n",
               config.vlan.c_str(), strerror(errno));
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
                    if (strcmp(ifa_tmp->ifa_name, config.vlan.c_str()) == 0) {
                        struct sockaddr_in *in = (struct sockaddr_in *)ifa_tmp->ifa_addr;
                        bind_client_addr = true;
                        client_addr = *in;
                        client_addr.sin_family = AF_INET;
                        client_addr.sin_port = htons(RELAY_PORT);
                    }
                }
                ifa_tmp = ifa_tmp->ifa_next;
            }
            freeifaddrs(ifa);
        }

        if (bind_client_addr) {
            break;
        }

        syslog(LOG_WARNING, "[DHCPV4_RELAY] Retry #%d to bind to sockets on interface %s\n", ++retry, config.vlan.c_str());
        sleep(5);
    } while (retry < 6);

    if ((!bind_client_addr) || (bind(client_sock, (sockaddr *)&client_addr, sizeof(client_addr)) == -1)) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] bind: Failed to bind socket to global ipv4 address on interface %s after %d retries with %s\n",
               config.vlan.c_str(), retry, strerror(errno));
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
    config.lo_sock = lo_sock;
#endif
    return 0;
}

uint8_t encode_tlv(uint8_t *buf, uint8_t t, uint8_t l, uint8_t *v) {
    *buf = t;
    *(buf + DHCP_SUB_OPT_TLV_LENGTH_OFFSET) = l;
    memcpy((buf + DHCP_SUB_OPT_TLV_HEADER_LEN), v, l);

    return (l + DHCP_SUB_OPT_TLV_HEADER_LEN);
}

void encode_relay_option(pcpp::DhcpLayer *dhcp_pkt, relay_config *config) {
    uint8_t buf[256] = {0};
    uint8_t buf_offset = 0;

    auto vrf = vlan_vrf_map[config->vlan.c_str()];

    /* Get interface alias */
    std::string intf_alias;
    if (phy_interface_alias_map.find(config->phy_interface) != phy_interface_alias_map.end()) {
        intf_alias = phy_interface_alias_map[config->phy_interface];
    } else {
        std::shared_ptr<swss::Table> port_tbl =
            std::make_shared<swss::Table>(config->config_db.get(), CFG_PORT_TABLE_NAME);
        port_tbl->hget(config->phy_interface.c_str(), "alias", intf_alias);
        phy_interface_alias_map[config->phy_interface] = intf_alias;
    }

    /* Encode circuit ID sub-option */
    /* | 1 | 4 | hostname:interface_alias:vlan | */
    std::string circuit_id = config->hostname + ":" + intf_alias + ":" + config->vlan;
    auto offset = encode_tlv(buf, OPTION82_SUBOPT_CIRCUIT_ID, circuit_id.length(),
                             (uint8_t *)circuit_id.c_str());
    buf_offset += offset;

    /* Encode remote ID sub-option */
    /* | 2 | 6 | my_mac| */
    offset = encode_tlv((buf + buf_offset), OPTION82_SUBOPT_REMOTE_ID,
                        MAC_ADDR_LEN, (uint8_t *)(config->host_mac_addr));
    buf_offset += offset;

    /* TODO: this sub-option should be set if source interface selection is enabled */
    /* | 5 | 4 | ipv4 | */
    if (config->link_selection_opt == "enable") {
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
    if (config->vrf_selection_opt == "enable") {
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
               MAX_DHCP_PKT_SIZE, config->vlan.c_str());
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
        encode_relay_option(dhcp_pkt, &config);
    } else {
        /* If the relay packet is from another relay, we should act based on
           configuration of agent_relay_mode.
           forward_and_append - Forward the packet with appending relay agent.
           forward_and_replace - Delete existing option 82 and add my relay option.
           forward_untouched - Forward without adding my relay information.
           discard - Discard the incoming packet.
         */
        if (config.agent_relay_mode == "forward_and_replace") {
            dhcp_pkt->removeOption(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
            encode_relay_option(dhcp_pkt, &config);
        } else if (config.agent_relay_mode == "discard") {
            syslog(LOG_INFO, "[DHCPV4_RELAY] agent relay mode is discard, dropping the packet %s",
                   config.vlan.c_str());
            return;
        } else if (config.agent_relay_mode == "forward_untouched") {
            syslog(LOG_INFO,
                   "[DHCPV4_RELAY] agent relay mode is forward untouch,"
                   " not appending self relay info %s",
                   config.vlan.c_str());
        } else {
            /* By default it will be forward_and_append */
            encode_relay_option(dhcp_pkt, &config);
        }
    }

    /* Increase the hop count */
    /*TODO: check hops count is less than max hops count allowed */
    dhcp_pkt->getDhcpHeader()->hops = dhcp_pkt->getDhcpHeader()->hops + 1;

    int sock = config.vrf_sock;
    uint32_t index = 0;
    for (auto server : config.servers_sock) {
        if (send_udp(sock, (uint8_t *)dhcp_pkt->getDhcpHeader(), server, dhcp_pkt->getHeaderLen())) {
            syslog(LOG_INFO, "[DHCPV4_RELAY] DHCP packet is sent to configured server: %s, interface: %s",
                   config.servers[index].c_str(), config.vlan.c_str());
            dhcp_cntr_table.increment_counter(config.vlan, "TX", (int)dhcp_pkt->getMessageType());
        } else {
            syslog(LOG_NOTICE, "[DHCPV4_RELAY] DHCP packet sending FAILED for configured server: %s, interface: %s",
                   config.servers[index].c_str(), config.vlan.c_str());
            // increment drop counter
            dhcp_cntr_table.increment_counter(config.vlan, "TX", DHCPv4_MESSAGE_TYPE_DROP);
        }
        index++;
    }
}

uint8_t *decode_tlv(const uint8_t *buf, uint8_t t, uint8_t &l, uint32_t options_total_size) {
    uint8_t *temp = (uint8_t *)buf;
    uint8_t len = 0;

    while (temp && (len < options_total_size)) {
        len = *(temp + DHCP_SUB_OPT_TLV_LENGTH_OFFSET);
        if (t == *temp) {
            syslog(LOG_INFO, "[DHCPV4_INFO] Decoding realy agent sub-option %d of len %d\n", t, len);
            l = len;
            return (temp + DHCP_SUB_OPT_TLV_HEADER_LEN);
        }
        temp += (len + DHCP_SUB_OPT_TLV_HEADER_LEN);
    }
    return NULL;
}

/**
 * @code                void to_client(pcpp::DhcpLayer* dhcp_pkt, std::unordered_map<std::string,
                                        relay_config > *vlans, std::string src_ip);
 *
 * @brief               API will send DHCP relay message to client.
 *
 * @param dhcp_pkt      DHCP layer class, which will have information of DHCP packet.
 * @param vlans         Client information including socket to send DHCP packet to client.
 *
 * @return              none
 */
void to_client(pcpp::DhcpLayer *dhcp_pkt, std::unordered_map<std::string, relay_config> *vlans,
               std::string src_ip) {
    struct ifaddrs *ifa, *ifa_tmp;
    struct sockaddr_in target_addr = {0};
    uint32_t giaddr = dhcp_pkt->getDhcpHeader()->gatewayIpAddress;
    uint32_t broadcast_addr = DHCP_BROADCAST_IPADDR;
    std::unordered_map<std::string, relay_config>::iterator config_itr = vlans->end();

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
    if (options_ptr == NULL) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Relay options for reply packets are missing from server %s",
               src_ip.c_str());
        return;
    }

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

    std::string vlan_interface;
    auto vlan_intf_pos = circuit_id.rfind(':');
    if (vlan_intf_pos != std::string::npos) {
        vlan_interface = circuit_id.substr(vlan_intf_pos + 1);
    }

    if (vlan_interface.length() > 0) {
        config_itr = vlans->find(vlan_interface);
        if (config_itr == vlans->end()) {
            syslog(LOG_INFO,
                   "[DHCPV4_RELAY] Vlan config not found for the circuit"
                   "id encoded interface  %s\n",
                   vlan_interface.c_str());
        }
    }

    /* If we couldnt able to find vlan config using circuit ID
       Walk through all the interfaces and match for giaddrs. */
    if (config_itr == vlans->end()) {
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
        //  find vlan attach using vlan map. Relay config is mapped to vlan.

        /* Expecting interface is SVI interface of vlan */
        auto config_itr = vlans->find(intf_name);
        if (config_itr == vlans->end()) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Config not found for vlan %s\n", intf_name.c_str());
            return;
        }
    } else {
        freeifaddrs(ifa);
    }
    auto config = config_itr->second;

    dhcp_cntr_table.increment_counter(config.vlan, "RX", (int)dhcp_pkt->getMessageType());
    /* TODO: Also check it is matching remote ID*/

    memcpy(&target_addr.sin_addr, &broadcast_addr, sizeof(struct in_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(CLIENT_PORT);

    /* TODO: Send unicast message to client if BOOTP flag from client is set to unicast */

    dhcp_pkt->removeOption(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS);
    if (send_udp(config.client_sock, (uint8_t *)dhcp_pkt->getDhcpHeader(), target_addr, dhcp_pkt->getHeaderLen())) {
        syslog(LOG_INFO, "[DHCPV4_RELAY] dhcp relay message is broadcast to client %s from server %s",
               config.vlan.c_str(), src_ip.c_str());
        dhcp_cntr_table.increment_counter(config.vlan, "TX", (int)dhcp_pkt->getMessageType());
    }
}

bool string_to_mac_addr(const std::string &mac_str, std::array<uint8_t, 6> &mac_addr) {
    if (mac_str.size() != 17) {
        return false;
    }

    std::istringstream iss(mac_str);
    int byte;
    char separator;

    for (size_t i = 0; i < mac_addr.size(); ++i) {
        if (!(iss >> std::hex >> byte)) {
            return false;
        }
        mac_addr[i] = static_cast<uint8_t>(byte);

        if (i < mac_addr.size() - 1) {
            if (!(iss >> separator) || (separator != ':' && separator != '-')) {
                return false;
            }
        }
    }

    return true;
}

/**
 * @code                update_vlan_mapping(std::string vlan, bool is_add);
 *
 * @brief               build vlan member interface to vlan mapping table
 *
 * @param vlan          vlan name string
 * @param add           add or delete entry
 *
 * @return              none
 */
/**
 * @brief Updates the VLAN mapping for a given VLAN.
 *
 * This function retrieves all VLAN members for the specified VLAN from the configuration database
 * and updates the global VLAN map with the interface and VLAN information.
 *
 * @param vlan The VLAN identifier as a string.
 * @param cfgdb A shared pointer to the configuration database connector.
 */
void update_vlan_mapping(std::string vlan, bool is_add) {
#ifdef UNIT_TEST
    std::vector<std::string> keys;
    swss::Table vlan_member_table(config_db.get(), "VLAN_MEMBER");
    vlan_member_table.getKeys(keys);
#else
    auto match_pattern = std::string("VLAN_MEMBER|") + vlan + std::string("|*");
    auto keys = config_db->keys(match_pattern);
#endif
    for (auto &itr : keys) {
        auto found = itr.find_last_of('|');
        auto interface = itr.substr(found + 1);
        if (is_add) {
            vlan_map[interface] = vlan;
            dhcp_cntr_table.initialize_interface(vlan);
            syslog(LOG_INFO, "[DHCPV4_RELAY] Add <%s, %s> into interface vlan map\n", interface.c_str(), vlan.c_str());
        } else {
            vlan_map.erase(interface);
            dhcp_cntr_table.remove_interface(vlan);
            syslog(LOG_INFO, "[DHCPV4_RELAY] Remove <%s, %s> from interface vlan map\n", interface.c_str(), vlan.c_str());
        }
    }

    /* get VRF attached to the vlan from VLAN_INTERFACE table */
    if (is_add) {
        std::string value;
        std::shared_ptr<swss::Table> vlan_intf_tbl = std::make_shared<swss::Table>(config_db.get(), CFG_VLAN_INTF_TABLE_NAME);
        vlan_intf_tbl->hget(vlan, "vrf_name", value);
        if (value.size() <= 0) {
            /* use default instance as vrf */
            vlan_vrf_map[vlan] = "default";
        } else {
            vlan_vrf_map[vlan] = value;
        }
    } else {
        vlan_vrf_map.erase(vlan);
    }
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
    auto vlans = reinterpret_cast<std::unordered_map<std::string, struct relay_config> *>(arg);
    struct sockaddr_ll sll;
    socklen_t slen = sizeof(sll);
    timeval time;
    int pkts_num = 0;
    char interface_name[IF_NAMESIZE];

    while (pkts_num++ < BATCH_SIZE) {
        auto buffer_sz = recvfrom(fd, client_recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&sll, &slen);
        if (buffer_sz <= 0) {
            if (errno != EAGAIN) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] recv: Failed to receive data at filter socket: %s\n", strerror(errno));
            }
            return;
        }

        if (if_indextoname(sll.sll_ifindex, interface_name) == NULL) {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid input interface index %d\n", sll.sll_ifindex);
            continue;
        }
        std::string intf(interface_name);

        gettimeofday(&time, nullptr);

        // Construct raw socket.
        pcpp::RawPacket raw_packet(static_cast<const uint8_t *>(client_recv_buffer), buffer_sz, time, false);

        pcpp::Packet raw_pkt(&raw_packet);

        /* Extract packets in each layers */
        pcpp::EthLayer *eth_layer = raw_pkt.getLayerOfType<pcpp::EthLayer>();
        if (eth_layer == nullptr) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid Ethernet packet from interface  %s\n", intf.c_str());
            return;
        }

        pcpp::IPv4Layer *ip_layer = raw_pkt.getLayerOfType<pcpp::IPv4Layer>();
        if (ip_layer == nullptr) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid IP packet from interface  %s\n", intf.c_str());
            return;
        }
        auto src_ip = ip_layer->getSrcIPv4Address().toString();

        pcpp::UdpLayer *udp_layer = raw_pkt.getLayerOfType<pcpp::UdpLayer>();
        if (udp_layer == nullptr) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid UDP packet from interface  %s\n", intf.c_str());
            return;
        }

        pcpp::DhcpLayer *dhcp_pkt = raw_pkt.getLayerOfType<pcpp::DhcpLayer>();
        if (dhcp_pkt == nullptr) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid DHCP packet from interface  %s\n", intf.c_str());
            return;
        }

        if (dhcp_pkt->getDhcpHeader()->opCode == BOOTPREQUEST) {
            auto vlan = vlan_map.find(intf);
            if (vlan == vlan_map.end()) {
                if (intf.find(CLIENT_IF_PREFIX) != std::string::npos) {
                    syslog(LOG_WARNING, "[DHCPV4_RELAY] Invalid input interface %s\n", interface_name);
                }
                continue;
            }
            auto config_itr = vlans->find(vlan->second);
            if (config_itr == vlans->end()) {
                syslog(LOG_WARNING, "[DHCPV4_RELAY] Config not found for vlan %s\n", vlan->second.c_str());
                continue;
            }
            auto config = config_itr->second;
            config_itr->second.phy_interface = intf;

            dhcp_cntr_table.increment_counter(config.vlan, "RX", (int)dhcp_pkt->getMessageType());
            from_client(dhcp_pkt, config_itr->second);
        } else if (dhcp_pkt->getDhcpHeader()->opCode == BOOTPREPLY) {
            /* TODO: This work around need to be fixed.
             *       Currently we are receiving same dhcp reply packet on physical interface.
             *       on SVI interface(VLAN) and on the bridge.
             *       Trap is added for DHCP packet on all interface.
             */
            if ((intf.find("Ethernet") == std::string::npos) &&
                (intf.find("Bridge") == std::string::npos)) {
                to_client(dhcp_pkt, vlans, src_ip);
            }
        } else {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Received a invalid DHCPv4 packet\n");
            return;
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

void config_event_callback(evutil_socket_t fd, short event, void *arg) {
    std::unordered_map<std::string, relay_config> *vlans = static_cast<std::unordered_map<std::string, relay_config> *>(arg);
    event_config received_event;
    ssize_t bytes_read = read(fd, &received_event, sizeof(received_event));

    if (bytes_read == sizeof(received_event)) {
        if (received_event.type == DHCPv4_RELAY_CONFIG_UPDATE) {
            relay_config *relay_msg = static_cast<relay_config *>(received_event.msg);
            if (relay_msg) {
                syslog(LOG_INFO, "[DHCPV4_RELAY] Processing config update: VLAN %s", relay_msg->vlan.c_str());

                if (relay_msg->is_add) {
                    if (vlans->find(relay_msg->vlan) == vlans->end()) {
                        /*If entry not exist then creating the entry with empty structure.*/
                        (*vlans)[relay_msg->vlan] = relay_config{};
                        (*vlans)[relay_msg->vlan].vlan = relay_msg->vlan;
                        (*vlans)[relay_msg->vlan].config_db = config_db;
                        (*vlans)[relay_msg->vlan].state_db = state_db;
                        update_vlan_mapping(relay_msg->vlan, true);
                        if (prepare_vlan_sockets((*vlans)[relay_msg->vlan]) == -1) {
                            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create Vlan listen socket");
                            exit(EXIT_FAILURE);
                        }
                        /* Intially filling the vlan interface IP address. */
                        if (relay_msg->source_interface.empty()) {
                            prepare_relay_interface_config((*vlans)[relay_msg->vlan]);
                        }
                    }

                    if ((*vlans)[relay_msg->vlan].servers != relay_msg->servers) {
                        (*vlans)[relay_msg->vlan].servers = relay_msg->servers;
                        prepare_relay_server_config((*vlans)[relay_msg->vlan]);
                    }

                    /* Compare the existing vrf value and the new DB updated vrf value for vrf modification case. */
                    if ((*vlans)[relay_msg->vlan].vrf != relay_msg->vrf) {
                        /* Decrement the ref count for old vrf value in the vrf_sock_map and after decrement
                         * if the value is zero then close the client socket and delete the entry in the map. */
                        if (vrf_sock_map.find((*vlans)[relay_msg->vlan].vrf) != vrf_sock_map.end()) {
                            vrf_sock_map[(*vlans)[relay_msg->vlan].vrf].ref_count--;
                            if (vrf_sock_map[(*vlans)[relay_msg->vlan].vrf].ref_count == 0) {
                                close((*vlans)[relay_msg->vlan].vrf_sock);
                                vrf_sock_map.erase((*vlans)[relay_msg->vlan].vrf);
                            }
                        }

                        /*Updating the new vrf value to vlans structure. */
                        (*vlans)[relay_msg->vlan].vrf = relay_msg->vrf;
                        /* For the new server vrf update case, if the entry exists in the vrf_sock_map then
                         * increment the ref count only else create a socket and update the ref count. */
                        if (vrf_sock_map.find(relay_msg->vrf) != vrf_sock_map.end()) {
                            (*vlans)[relay_msg->vlan].vrf_sock = vrf_sock_map[relay_msg->vrf.c_str()].sock;
                            vrf_sock_map[relay_msg->vrf].ref_count++;
                        } else {
                            if (prepare_vrf_sockets((*vlans)[relay_msg->vlan]) == -1) {
                                syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to create vrf listen socket");
                                exit(EXIT_FAILURE);
                            }
                        }
                    }
                    if ((*vlans)[relay_msg->vlan].source_interface != relay_msg->source_interface) {
                        (*vlans)[relay_msg->vlan].source_interface = relay_msg->source_interface;
                        prepare_relay_interface_config((*vlans)[relay_msg->vlan]);
                    }

                    (*vlans)[relay_msg->vlan].link_selection_opt = relay_msg->link_selection_opt;
                    (*vlans)[relay_msg->vlan].server_id_override_opt = relay_msg->server_id_override_opt;
                    (*vlans)[relay_msg->vlan].vrf_selection_opt = relay_msg->vrf_selection_opt;
                    (*vlans)[relay_msg->vlan].agent_relay_mode = relay_msg->agent_relay_mode;
                } else {
                    if (vlans->find(relay_msg->vlan) != vlans->end()) {
                        /* In case of vlan deletion, close all the sockets.*/
                        if ((*vlans)[relay_msg->vlan].client_sock > 0) {
                            close((*vlans)[relay_msg->vlan].client_sock);
                        }
                        if ((*vlans)[relay_msg->vlan].lo_sock > 0) {
                            close((*vlans)[relay_msg->vlan].lo_sock);
                        }
                        if ((*vlans)[relay_msg->vlan].vrf_sock > 0) {
                            vrf_sock_map[(*vlans)[relay_msg->vlan].vrf].ref_count--;
                            if (vrf_sock_map[(*vlans)[relay_msg->vlan].vrf].ref_count == 0) {
                                close((*vlans)[relay_msg->vlan].vrf_sock);
                                vrf_sock_map.erase((*vlans)[relay_msg->vlan].vrf);
                            }
                        }
                        vlans->erase(relay_msg->vlan);
                        syslog(LOG_INFO, "[DHCPV4_RELAY] Deleted VLAN %s from configuration", relay_msg->vlan.c_str());
                        update_vlan_mapping(relay_msg->vlan, false);
                    } else {
                        syslog(LOG_WARNING, "[DHCPV4_RELAY] Attempted to delete non-existent VLAN %s", relay_msg->vlan.c_str());
                    }
                }
                delete relay_msg;
            }
        } else if (received_event.type == DHCPv4_RELAY_INTERFACE_UPDATE) {
            relay_config *relay_msg = static_cast<relay_config *>(received_event.msg);
            if (relay_msg) {
                syslog(LOG_INFO, "[DHCPV4_RELAY] Updating source interface for VLAN %s", relay_msg->vlan.c_str());
                if (relay_msg->is_add) {
                    (*vlans)[relay_msg->vlan].src_intf_sel_addr = relay_msg->src_intf_sel_addr;
                } else {
                    memset(&(*vlans)[relay_msg->vlan].src_intf_sel_addr, 0, sizeof(sockaddr_in));
                }
                delete relay_msg;
            }
        } else if (received_event.type == DHCPv4_RELAY_METADATA_UPDATE) {
            relay_config *device_data = static_cast<relay_config *>(received_event.msg);
            if (device_data) {
                syslog(LOG_INFO, "[DHCPV4_RELAY] Processing Device Metadata Event Update.");

                for (auto &vlan : *vlans) {
                    vlan.second.hostname = device_data->hostname;
                    std::copy(std::begin(device_data->host_mac_addr), std::end(device_data->host_mac_addr),
                              std::begin(vlan.second.host_mac_addr));
                }
                delete device_data;
            }
        }
    } else {
        syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to read config update: expected %lu bytes, got %zd bytes", sizeof(received_event), bytes_read);
    }
}

/**
 * @code                loop_relay(std::unordered_map<relay_config> &vlans);
 *
 * @brief               main loop: configure sockets, create libevent base, start server listener thread
 *
 * @param vlans         list of vlans retrieved from config_db
 */

/**
 * @brief Main loop for the DHCP relay functionality.
 *
 * This function sets up the necessary event base and socket listeners for
 * handling DHCP relay operations. It initializes connections to the state
 * and configuration databases, sets up event listeners for client and server
 * sockets, and prepares VLAN-specific configurations.
 *
 * @param vlans A reference to an unordered map containing VLAN configurations.
 *
 */
void loop_relay(std::unordered_map<std::string, relay_config> &vlans) {
    base = event_base_new();
    if (base == NULL) {
        syslog(LOG_ERR, "[DHCPV4_RELAY] libevent: Failed to create event base\n");
        exit(EXIT_FAILURE);
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
                                           config_event_callback, reinterpret_cast<void *>(&vlans));
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
                               reinterpret_cast<void *>(&vlans));
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
    dhcp_mgr.initialize_config_listner();

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
