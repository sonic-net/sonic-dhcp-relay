#include <errno.h>
#include <unistd.h>
#include <event.h>
#include <sstream>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <signal.h>

#include "configdb.h"
#include "sonicv2connector.h"
#include "dbconnector.h" 
#include "config_interface.h"

struct event_base *base;
struct event *ev_sigint;
struct event *ev_sigterm;
static std::string vlan_member = "VLAN_MEMBER|";
static std::string counter_table = "DHCPv6_COUNTER_TABLE|";

static uint8_t client_recv_buffer[BUFFER_SIZE];
static uint8_t server_recv_buffer[BUFFER_SIZE];

/* DHCPv6 filter */
/* sudo tcpdump -dd "inbound and ip6 dst ff02::1:2 && udp dst port 547" */

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

/* DHCPv6 counter name map */
std::map<int, std::string> counterMap = {
    {DHCPv6_MESSAGE_TYPE_UNKNOWN, "Unknown"},
    {DHCPv6_MESSAGE_TYPE_SOLICIT, "Solicit"},
    {DHCPv6_MESSAGE_TYPE_ADVERTISE, "Advertise"},
    {DHCPv6_MESSAGE_TYPE_REQUEST, "Request"},
    {DHCPv6_MESSAGE_TYPE_CONFIRM, "Confirm"},
    {DHCPv6_MESSAGE_TYPE_RENEW, "Renew"},
    {DHCPv6_MESSAGE_TYPE_REBIND, "Rebind"},
    {DHCPv6_MESSAGE_TYPE_REPLY, "Reply"},
    {DHCPv6_MESSAGE_TYPE_RELEASE, "Release"},
    {DHCPv6_MESSAGE_TYPE_DECLINE, "Decline"},
    {DHCPv6_MESSAGE_TYPE_RECONFIGURE, "Reconfigure"},
    {DHCPv6_MESSAGE_TYPE_INFORMATION_REQUEST, "Information-Request"},
    {DHCPv6_MESSAGE_TYPE_RELAY_FORW, "Relay-Forward"},
    {DHCPv6_MESSAGE_TYPE_RELAY_REPL, "Relay-Reply"},
    {DHCPv6_MESSAGE_TYPE_MALFORMED, "Malformed"}
};

/* interface to vlan mapping */
std::unordered_map<std::string, std::string> vlan_map;

/* ipv6 address to vlan name mapping */
std::unordered_map<std::string, std::string> addr_vlan_map;

/**
 * @code                bool inline isIPv6Zero(const in6_addr &addr)
 * 
 * @brief               check if ipv6 address is zero
 *
 * @param addr          ipv6 address
 *
 * @return              bool
 */
bool inline isIPv6Zero(const in6_addr &addr) {
    return (memcmp(&addr, &in6addr_any, sizeof(in6addr_any)) == 0);
}

/* Options Class Definition */

// add single option
bool Options::Add(OptionCode key, const uint8_t *value, uint16_t len) {
    std::vector<uint8_t> option_v(value, value + len);
    m_options[key] = option_v;
    return true;
}

// delete single option based on OptionCode
bool Options::Delete(OptionCode key) {
    if (m_options.find(key) == m_options.end()) {
        return false;
    }
    m_options.erase(key);
    return true;
}

// get a copy of option value based on OptionCode
std::vector<uint8_t> Options::Get(OptionCode key) {
    if (m_options.find(key) == m_options.end()) {
        return std::vector<uint8_t>{};
    }
    return m_options[key];
}

// marshal options to binary, return pointer of binary vector
std::vector<uint8_t> *Options::MarshalBinary() {
    if (m_options.empty()) {
        return nullptr;
    }
    if (!m_list.empty()) {
        syslog(LOG_WARNING, "options already marshaled !!!");
        return &m_list;
    }
    for (auto &itr : m_options) {
        uint16_t type = htons(itr.first);
        uint16_t length = htons(itr.second.size());
        m_list.push_back(((uint8_t *)&type)[0]);
        m_list.push_back(((uint8_t *)&type)[1]);
        m_list.push_back(((uint8_t *)&length)[0]);
        m_list.push_back(((uint8_t *)&length)[1]);
        m_list.insert(m_list.end(), itr.second.begin(), itr.second.end());
    }
    return &m_list;
}

// unmarshal options binary to options map
bool Options::UnmarshalBinary(const uint8_t *packet, uint16_t length) {
    while (length >= sizeof(dhcpv6_option)) {
        auto option = (dhcpv6_option *)packet;
        auto type = ntohs(option->option_code);
        if (type > DHCPv6_OPTION_LIMIT) {
            syslog(LOG_WARNING, "Option type %d is invalid \n", type);
            return false;
        }
        auto len = ntohs(option->option_length);
        if (len + sizeof(dhcpv6_option) > length) {
            syslog(LOG_WARNING, "Unmarshal packet error: option %d length %d over range\n", type, len);
            return false;
        }
        auto value_ptr = packet + sizeof(dhcpv6_option);
        std::vector<uint8_t> option_v(value_ptr, value_ptr + len);
        m_options[type] = option_v;
        auto offset = sizeof(dhcpv6_option) + len;
        length -= offset;
        packet += offset;
    }
    if (length > 0) {
        syslog(LOG_WARNING, "Options unmarshal incomplete, %d bytes left", length);
    }
    return true;
}

/* RelayMsg Class Definitions */

// marshal dhcpv6 relay message class to binary
uint8_t *RelayMsg::MarshalBinary(uint16_t &len) {
    if (m_buffer == nullptr) {
        m_buffer.reset(new (std::nothrow)uint8_t[BUFFER_SIZE]);
        if (!m_buffer) {
            syslog(LOG_ERR, "Failed to init relay msg buffer\n");
            exit(1);
        }
    }

    auto ptr = m_buffer.get();
    std::memcpy(ptr, &m_msg_hdr, sizeof(dhcpv6_relay_msg));
    len = sizeof(dhcpv6_relay_msg);

    auto opt = m_option_list.MarshalBinary();
    if (opt && !opt->empty()) {
        if (opt->size() + sizeof(dhcpv6_relay_msg) > BUFFER_SIZE) {
            syslog(LOG_WARNING, "Failed to marshal relay msg, packet size %lu over limit\n",
                   opt->size() + sizeof(dhcpv6_relay_msg));
            len = 0;
            return nullptr;
        }
        std::memcpy(ptr + sizeof(dhcpv6_relay_msg), opt->data(), opt->size());
        len += opt->size();
    }

    return ptr;
}

// unmarshal dhcpv6 relay message binary to RelayMsg class
bool RelayMsg::UnmarshalBinary(const uint8_t *packet, uint16_t len) {
    if (len < sizeof(dhcpv6_relay_msg)) {
        syslog(LOG_WARNING, "Unmarshal relay msg error, invalid packet length %d", len);
        return false;
    }
    auto hdr = (dhcpv6_relay_msg *)packet;
    m_msg_hdr.msg_type = hdr->msg_type;
    m_msg_hdr.hop_count = hdr->hop_count;
    std::memcpy(&m_msg_hdr.link_address, &hdr->link_address, sizeof(struct in6_addr));
    std::memcpy(&m_msg_hdr.peer_address, &hdr->peer_address, sizeof(struct in6_addr));
    if (!m_option_list.UnmarshalBinary(packet + sizeof(dhcpv6_relay_msg), len - sizeof(dhcpv6_relay_msg))) {
        char link_addr_str[INET6_ADDRSTRLEN], peer_addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &m_msg_hdr.link_address, link_addr_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &m_msg_hdr.peer_address, peer_addr_str, INET6_ADDRSTRLEN);
        syslog(LOG_WARNING, "Unmarshal relay msg (type %d, link addr %s, peer addr %s) error, invalid options",
               m_msg_hdr.msg_type, link_addr_str, peer_addr_str);
        return false;
    }
    return true;
}

/* DHCPv6Msg Class Definitions */

// marshal dhcpv6 message class to binary
uint8_t *DHCPv6Msg::MarshalBinary(uint16_t &len) {
    if (m_buffer == nullptr) {
        m_buffer.reset(new (std::nothrow)uint8_t[BUFFER_SIZE]);
        if (!m_buffer) {
            syslog(LOG_ERR, "Failed to init dhcpv6 msg buffer\n");
            exit(1);
        }
    }

    auto ptr = m_buffer.get();
    std::memcpy(ptr, &m_msg_hdr, sizeof(dhcpv6_msg));
    len = sizeof(dhcpv6_msg);

    auto opt = m_option_list.MarshalBinary();
    if (opt && !opt->empty()) {
        if (opt->size() + sizeof(dhcpv6_msg) > BUFFER_SIZE) {
            syslog(LOG_WARNING, "Failed to marshal dhcpv6 msg, packet size %lu over limit\n",
                   opt->size() + sizeof(dhcpv6_msg));
            len = 0;
            return nullptr;
        }
        std::memcpy(ptr + sizeof(dhcpv6_msg), opt->data(), opt->size());
        len += opt->size();
    }

    return ptr;
}

// unmarshal dhcpv6 message binary to DHCPv6Msg class
bool DHCPv6Msg::UnmarshalBinary(const uint8_t *packet, uint16_t len) {
    if (len < sizeof(dhcpv6_msg)) {
        syslog(LOG_WARNING, "Unmarshal DHCPv6 msg error, invalid packet length %d", len);
        return false;
    }
    auto hdr = (dhcpv6_msg *)packet;
    m_msg_hdr.msg_type = hdr->msg_type;
    std::memcpy(&m_msg_hdr.xid, &hdr->xid, sizeof(m_msg_hdr.xid));
    if (!m_option_list.UnmarshalBinary(packet + sizeof(dhcpv6_msg), len - sizeof(dhcpv6_msg))) {
        syslog(LOG_WARNING, "Unmarshal DHCPv6 msg (type %d) error, invalid options", m_msg_hdr.msg_type);
        return false;
    }
    return true;
}

/**
 * @code                initialize_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname);
 *
 * @brief               initialize the counter for interface
 *
 * @param std::shared_ptr<swss::DBConnector> state_db     state_db connector pointer
 * @param ifname        interface name
 * 
 * @return              none
 */
void initialize_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname) {
    std::string table_name = counter_table + ifname;
    for (auto &intr : counterMap) {
        state_db->hset(table_name, intr.second, toString(0)); 
    }
}

/**
 * @code                void increase_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname, uint8_t msg_type);
 *
 * @brief               increase the counter in state_db with count of each DHCPv6 message types
 *
 * @param std::shared_ptr<swss::DBConnector> state_db,     state_db connector pointer
 * @param ifname        interface name
 * @param msg_type      dhcpv6 message type to be increased in counter
 * 
 * @return              none
 */
void increase_counter(std::shared_ptr<swss::DBConnector> state_db, std::string &ifname, uint8_t msg_type) {
    if (counterMap.find(msg_type) == counterMap.end()) {
        syslog(LOG_WARNING, "Unexpected message type %d(0x%x)\n", msg_type, msg_type);
        return;
    }
    std::string table_name = counter_table + ifname;
    std::string type = counterMap.find(msg_type)->second;
    auto count_str = state_db->hget(table_name, type);
    if (count_str == nullptr) {
        state_db->hset(table_name, type, toString(1));
    } else {
        auto count = atoll(count_str.get()->c_str());
        state_db->hset(table_name, type, toString(count + 1));
    }
}

/**
 * @code                std::string toString(uint64_t count);
 *
 * @brief               convert uint16_t to string
 *
 * @param count         count of messages in counter
 * 
 * @return              count in string
 */
std::string toString(uint64_t count) {
    std::stringstream ss;
    ss << count;
    std::string countValue = ss.str();
    return countValue;
}

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
const struct ether_header *parse_ether_frame(const uint8_t *buffer, const uint8_t **out_end) {
    auto temp = buffer;
    *out_end = buffer + sizeof(struct ether_header);
    return (const struct ether_header *)temp;
}

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
const struct ip6_hdr *parse_ip6_hdr(const uint8_t *buffer, const uint8_t **out_end) {
    auto temp = buffer;
    (*out_end) = buffer + sizeof(struct ip6_hdr);
    return (struct ip6_hdr *)temp;
}

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
const struct udphdr *parse_udp(const uint8_t *buffer, const uint8_t **out_end) {
    auto temp = buffer;
    (*out_end) = buffer + sizeof(struct udphdr);
    return (const struct udphdr *)temp;
}

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
const struct dhcpv6_msg *parse_dhcpv6_hdr(const uint8_t *buffer) {
    return (const struct dhcpv6_msg *)buffer;
}

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
const struct dhcpv6_relay_msg *parse_dhcpv6_relay(const uint8_t *buffer) {
    return (const struct dhcpv6_relay_msg *)buffer;
}

/**
 * @code                sock_open(const struct sock_fprog *fprog);
 *
 * @brief               prepare L2 socket to attach to "udp and port 547" filter 
 *
 * @param fprog         bpf filter "udp and port 547"
 *
 * @return              socket descriptor
 */
int sock_open(const struct sock_fprog *fprog)
{

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        syslog(LOG_ERR, "socket: Failed to create socket\n");
        return -1;
    }

    evutil_make_listen_socket_reuseable(s);
    evutil_make_socket_nonblocking(s);

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = 0 // any interface
    };

    if (bind(s, (struct sockaddr *)&sll, sizeof sll) == -1) {
        syslog(LOG_ERR, "bind: Failed to bind to specified interface\n");
        (void) close(s);
        return -1;
    }

    if (fprog && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, fprog, sizeof *fprog) == -1) {
        syslog(LOG_ERR, "setsockopt: Failed to attach filter\n");
        (void) close(s);
        return -1;
    }

    int optval = 0;
    socklen_t optlen = sizeof(optval);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) == -1) {
        syslog(LOG_ERR, "getsockopt: Failed to get recv buffer size\n");
        (void) close(s);
        return -1;
    }

    int optval_new = RAWSOCKET_RECV_SIZE;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval_new, sizeof(optval_new)) == -1) {
        syslog(LOG_WARNING, "setsockopt: Failed to set recv buffer size to %d, use default value\n", optval_new);
    } else {
        syslog(LOG_INFO, "setsockopt: change raw socket recv buffer size from %d to %d\n", optval, optval_new);
    }

    return s;
}

/**
 * @code                        prepare_relay_config(relay_config &interface_config, int gua_sock, int filter);
 * 
 * @brief                       prepare for specified relay interface config: server and link address
 *
 * @param interface_config      pointer to relay config to be prepared
 * @param gua_sock            L3 socket used for relaying messages
 * @param filter                socket attached with filter
 *
 * @return                      none
 */
void prepare_relay_config(relay_config &interface_config, int gua_sock, int filter) {
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in6 non_link_local;
    sockaddr_in6 link_local;
    
    interface_config.gua_sock = gua_sock;
    interface_config.filter = filter; 

    for(auto server: interface_config.servers) {
        sockaddr_in6 tmp;
        if(inet_pton(AF_INET6, server.c_str(), &tmp.sin6_addr) != 1)
        {
            syslog(LOG_WARNING, "inet_pton: Failed to convert IPv6 address\n");
        }
        tmp.sin6_family = AF_INET6;
        tmp.sin6_flowinfo = 0;
        tmp.sin6_port = htons(RELAY_PORT);
        tmp.sin6_scope_id = 0; 
        interface_config.servers_sock.push_back(tmp);
    }

    if (getifaddrs(&ifa) == -1) {
        syslog(LOG_WARNING, "getifaddrs: Unable to get network interfaces\n");
        exit(1);
    }

    ifa_tmp = ifa;
    while (ifa_tmp) {
        if (ifa_tmp->ifa_addr && ifa_tmp->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
            if((strcmp(ifa_tmp->ifa_name, interface_config.interface.c_str()) == 0) && !IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {    
                non_link_local = *in6;
                break;
            }
            if((strcmp(ifa_tmp->ifa_name, interface_config.interface.c_str()) == 0) && IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {    
                link_local = *in6;
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    freeifaddrs(ifa); 
    
    if(!IN6_IS_ADDR_LINKLOCAL(&non_link_local.sin6_addr)) {
        interface_config.link_address = non_link_local;
    }
    else {
        interface_config.link_address = link_local;
    }
    char ipv6_str[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &interface_config.link_address.sin6_addr, ipv6_str, INET6_ADDRSTRLEN);
    addr_vlan_map[std::string(ipv6_str)] = interface_config.interface;
}

/**
 * @code                prepare_lo_socket(const char *lo);
 * 
 * @brief               prepare loopback interface socket for dual tor senario
 *
 * @param lo            loopback interface name
 *
 * @return              int
 */
int prepare_lo_socket(const char *lo) {
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in6 gua = {0};
    int lo_sock = -1;

    if ((lo_sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "socket: Failed to create gua socket on interface %s\n", lo);
        return -1;
    }

    evutil_make_listen_socket_reuseable(lo_sock);
    evutil_make_socket_nonblocking(lo_sock);

    if (getifaddrs(&ifa) == -1) {
        syslog(LOG_WARNING, "getifaddrs: Unable to get network interfaces with %s\n", strerror(errno));
    }
    bool bind_gua = false;
    ifa_tmp = ifa;
    while (ifa_tmp) {
        if (ifa_tmp->ifa_addr && (ifa_tmp->ifa_addr->sa_family == AF_INET6)) {
            if (strcmp(ifa_tmp->ifa_name, lo) == 0) {
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                if (!IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
                    bind_gua = true;
                    gua = *in6;
                    gua.sin6_family = AF_INET6;
                    gua.sin6_port = htons(RELAY_PORT);
                    break;
                }
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    freeifaddrs(ifa);

    if (!bind_gua || bind(lo_sock, (sockaddr *)&gua, sizeof(gua)) == -1) {
        syslog(LOG_ERR, "bind: Failed to bind socket on interface %s with %s\n", lo, strerror(errno));
        (void) close(lo_sock);
        return -1;
    }

    return lo_sock;
}

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
int prepare_vlan_sockets(int &gua_sock, int &lla_sock, relay_config &config) {
    struct ifaddrs *ifa, *ifa_tmp;
    sockaddr_in6 gua = {0}, lla = {0};

    if ((gua_sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "socket: Failed to create gua socket on interface %s\n", config.interface.c_str());
        return -1;
    }

    if ((lla_sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "socket: Failed to create lla socket on interface %s\n", config.interface.c_str());
        close(gua_sock);
        return -1;
    }

    evutil_make_listen_socket_reuseable(gua_sock);
    evutil_make_socket_nonblocking(gua_sock);
    evutil_make_listen_socket_reuseable(lla_sock);
    evutil_make_socket_nonblocking(lla_sock);

    int retry = 0;
    bool bind_gua = false;
    bool bind_lla = false;
    do {
        if (getifaddrs(&ifa) == -1) {
            syslog(LOG_WARNING, "getifaddrs: Unable to get network interfaces with %s\n", strerror(errno));
        }
        else {
            ifa_tmp = ifa;
            while (ifa_tmp) {
                if (ifa_tmp->ifa_addr && (ifa_tmp->ifa_addr->sa_family == AF_INET6)) {
                    if (strcmp(ifa_tmp->ifa_name, config.interface.c_str()) == 0) {
                        struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                        if (!IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
                            bind_gua = true;
                            gua = *in6;
                            gua.sin6_family = AF_INET6;
                            gua.sin6_port = htons(RELAY_PORT);
                        } else {
                            bind_lla = true;
                            lla = *in6;
                            lla.sin6_family = AF_INET6;
                            lla.sin6_port = htons(RELAY_PORT);
                        }
                    }
                }
                ifa_tmp = ifa_tmp->ifa_next;
            }
            freeifaddrs(ifa);
        }

        if (bind_gua && bind_lla) {
            break;
        }

        syslog(LOG_WARNING, "Retry #%d to bind to sockets on interface %s\n", ++retry, config.interface.c_str());
        sleep(5);
    } while (retry < 6);

    if ((!bind_gua) || (bind(gua_sock, (sockaddr *)&gua, sizeof(gua)) == -1)) {
        syslog(LOG_ERR, "bind: Failed to bind socket to global ipv6 address on interface %s after %d retries with %s\n",
               config.interface.c_str(), retry, strerror(errno));
        close(gua_sock);
        close(lla_sock);
        return -1;
    }

    if ((!bind_lla) || (bind(lla_sock, (sockaddr *)&lla, sizeof(lla)) == -1)) {
        syslog(LOG_ERR, "bind: Failed to bind socket to link local ipv6 address on interface %s after %d retries with %s\n",
               config.interface.c_str(), retry, strerror(errno));
        close(gua_sock);
        close(lla_sock);
        return -1;
    }
    return 0;
}


/**
 * @code                 relay_client(int sock, const uint8_t *msg, uint16_t len, ip6_hdr *ip_hdr, const ether_header *ether_hdr, relay_config *config);
 * 
 * @brief                construct relay-forward message
 *
 * @param sock           L3 socket for sending data to servers
 * @param msg            pointer to dhcpv6 message header position
 * @param len            size of data received
 * @param ip_hdr         pointer to IPv6 header
 * @param ether_hdr      pointer to Ethernet header
 * @param config         pointer to the relay interface config
 *
 * @return none
 */
void relay_client(const uint8_t *msg, uint16_t len, const ip6_hdr *ip_hdr, const ether_header *ether_hdr, relay_config *config) {    
    /* unmarshal dhcpv6 message to detect malformed message */
    DHCPv6Msg dhcpv6;
    auto result = dhcpv6.UnmarshalBinary(msg, len);
    if (!result) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_hdr->ip6_src, addr_str, INET6_ADDRSTRLEN);
        increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_MALFORMED);
        syslog(LOG_WARNING, "DHCPv6 option is invalid or contains malformed payload from %s\n", addr_str);
        return;
    }
    increase_counter(config->state_db, config->interface, dhcpv6.m_msg_hdr.msg_type);

    /* generate relay packet */
    class RelayMsg relay;
    relay.m_msg_hdr.msg_type = DHCPv6_MESSAGE_TYPE_RELAY_FORW;
    relay.m_msg_hdr.hop_count = 0;
    std::memcpy(&relay.m_msg_hdr.peer_address, &ip_hdr->ip6_src, sizeof(in6_addr));
    std::memcpy(&relay.m_msg_hdr.link_address, &config->link_address.sin6_addr, sizeof(in6_addr));

    /* insert relay options */
    if(config->is_option_79) {
        option_linklayer_addr option79;
        option79.link_layer_type = htons(1);
        std::memcpy(option79.link_layer_addr, &ether_hdr->ether_shost, sizeof(ether_hdr->ether_shost));
        relay.m_option_list.Add(OPTION_CLIENT_LINKLAYER_ADDR, (const uint8_t *)&option79, sizeof(option_linklayer_addr));
    }

    if(config->is_interface_id) {
        option_interface_id intf_id;
        intf_id.interface_id = config->link_address.sin6_addr;
        relay.m_option_list.Add(OPTION_INTERFACE_ID, (const uint8_t *)&intf_id, sizeof(option_interface_id));
    }
    /* Insert relay-msg option, use original dhcpv6 client message to keep the same option order. */
    relay.m_option_list.Add(OPTION_RELAY_MSG, msg, len);

    uint16_t relay_pkt_len = 0;
    auto relay_pkt = relay.MarshalBinary(relay_pkt_len);
    if (!relay_pkt_len || !relay_pkt) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_hdr->ip6_src, addr_str, INET6_ADDRSTRLEN);
        syslog(LOG_ERR, "Relay-forward marshal error, client dhcpv6 from %s", addr_str);
        return;
    }

    int sock = config->gua_sock;
    if (dual_tor_sock) {
        sock = config->lo_sock;
    }
    for(auto server: config->servers_sock) {
        if(send_udp(sock, relay_pkt, server, relay_pkt_len)) {
            increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
        }
    }
}

/**
 * @code                 relay_relay_forw(int sock, const uint8_t *msg, int32_t len, const ip6_hdr *ip_hdr, relay_config *config)
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
void relay_relay_forw(const uint8_t *msg, int32_t len, const ip6_hdr *ip_hdr, relay_config *config) {
    auto dhcp_relay_header = parse_dhcpv6_relay(msg);

    if (dhcp_relay_header->hop_count >= HOP_LIMIT) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_hdr->ip6_src, addr_str, INET6_ADDRSTRLEN);
        syslog(LOG_INFO, "Dropping relay-forward message from %s with hop count %d over limit",
               addr_str, dhcp_relay_header->hop_count);
        return;
    }

    RelayMsg relay;
    relay.m_msg_hdr.msg_type = DHCPv6_MESSAGE_TYPE_RELAY_FORW;
    memcpy(&relay.m_msg_hdr.peer_address, &ip_hdr->ip6_src, sizeof(in6_addr));
    relay.m_msg_hdr.hop_count = dhcp_relay_header->hop_count + 1;
    memset(&relay.m_msg_hdr.link_address, 0, sizeof(in6_addr));

    /* add relay-msg option */
    relay.m_option_list.Add(OPTION_RELAY_MSG, msg, len);

    // insert option82 for new relay-forward packet, we need this information
    // to get original relay-forward source interface for accurate counting in dualtor scenario
    // is_interface_id is by-default enabled in dualtor scenario
    if(config->is_interface_id) {
        option_interface_id intf_id;
        intf_id.interface_id = config->link_address.sin6_addr;
        relay.m_option_list.Add(OPTION_INTERFACE_ID, (const uint8_t *)&intf_id, sizeof(option_interface_id));
    }

    uint16_t send_buffer_len = 0;
    auto send_buffer = relay.MarshalBinary(send_buffer_len);
    if (!send_buffer_len || !send_buffer) {
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip_hdr->ip6_src, addr_str, INET6_ADDRSTRLEN);
        syslog(LOG_ERR, "Marshal relay-forward message from %s error", addr_str);
        return;
    }

    int sock = config->gua_sock;
    if (dual_tor_sock) {
        sock = config->lo_sock;
    }
    for(auto server: config->servers_sock) {
        if(send_udp(sock, send_buffer, server, send_buffer_len)) {
            increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_RELAY_FORW);
        }
    }
}

/**
 * @code                relay_relay_reply(int sock, const uint8_t *msg, int32_t len, relay_config *configs);
 * 
 * @brief               relay and unwrap a relay-reply message
 *
 * @param sock          L3 socket for sending data to servers
 * @param msg           pointer to dhcpv6 message header position
 * @param len           size of data received
 * @param config        relay interface config
 *
 * @return              none
 */
 void relay_relay_reply(const uint8_t *msg, int32_t len, relay_config *config) {
    class RelayMsg relay;
    auto result = relay.UnmarshalBinary(msg, len);
    if (!result) {
        increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_MALFORMED);
        syslog(LOG_WARNING, "Relay-reply option is invalid or contains malformed payload\n");
        return;
    }

    auto opt_value = relay.m_option_list.Get(OPTION_RELAY_MSG);
    if (opt_value.empty()) {
        increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_UNKNOWN);
        syslog(LOG_WARNING, "Option relay-msg not found");
        return;
    }
    auto dhcpv6 = opt_value.data();
    auto length = opt_value.size();
    auto msg_type = parse_dhcpv6_hdr(dhcpv6)->msg_type;

    struct sockaddr_in6 target_addr;
    memcpy(&target_addr.sin6_addr, &relay.m_msg_hdr.peer_address, sizeof(struct in6_addr));
    target_addr.sin6_family = AF_INET6;
    target_addr.sin6_flowinfo = 0;
    target_addr.sin6_port = htons(CLIENT_PORT);
    target_addr.sin6_scope_id = if_nametoindex(config->interface.c_str());

    int sock = config->lla_sock;
    if (isIPv6Zero(relay.m_msg_hdr.link_address)) {
        // relay.m_msg_hdr is packed member, use a temp variable for unaligned case
        struct in6_addr peer_addr = relay.m_msg_hdr.peer_address;
        if (!IN6_IS_ADDR_LINKLOCAL(&peer_addr))
            sock = config->gua_sock;
        target_addr.sin6_port = htons(RELAY_PORT);
    }

    if(send_udp(sock, dhcpv6, target_addr, length)) {
        increase_counter(config->state_db, config->interface, msg_type);
    }
}

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
void update_vlan_mapping(std::string vlan, std::shared_ptr<swss::DBConnector> cfgdb) {
    auto match_pattern = std::string("VLAN_MEMBER|") + vlan + std::string("|*");
    auto keys = cfgdb->keys(match_pattern);
    for (auto &itr : keys) {
        auto found = itr.find_last_of('|');
        auto interface = itr.substr(found + 1);
        vlan_map[interface] = vlan;
        syslog(LOG_INFO, "Add <%s, %s> into interface vlan map\n", interface.c_str(), vlan.c_str());
    }
}

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
void client_callback(evutil_socket_t fd, short event, void *arg) {
    auto vlans = reinterpret_cast<std::unordered_map<std::string, struct relay_config> *>(arg);
    struct sockaddr_ll sll;
    socklen_t slen = sizeof(sll);
    int pkts_num = 0;

    while (pkts_num++ < BATCH_SIZE) {
        auto buffer_sz = recvfrom(fd, client_recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&sll, &slen);
        if (buffer_sz <= 0) {
            if (errno != EAGAIN) {
                syslog(LOG_ERR, "recv: Failed to receive data at filter socket: %s\n", strerror(errno));
            }
            return;
        }
        char interfaceName[IF_NAMESIZE];
        if (if_indextoname(sll.sll_ifindex, interfaceName) == NULL) {
            syslog(LOG_WARNING, "Invalid input interface index %d\n", sll.sll_ifindex);
            continue;
        }

        std::string intf(interfaceName);
        auto vlan = vlan_map.find(intf);
        if (vlan == vlan_map.end()) {
            if (intf.find(CLIENT_IF_PREFIX) != std::string::npos) {
                syslog(LOG_WARNING, "Invalid input interface %s\n", interfaceName);
            }
            continue;
        }
        auto config_itr = vlans->find(vlan->second);
        if (config_itr == vlans->end()) {
            syslog(LOG_WARNING, "Config not found for vlan %s\n", vlan->second.c_str());
            continue;
        }
        auto config = config_itr->second;
        if (dual_tor_sock) {
            std::string state;
            config.mux_table->hget(intf, "state", state);
            if (state != "standby") {
                client_packet_handler(client_recv_buffer, buffer_sz, &config, intf);
            }
        } else {
            client_packet_handler(client_recv_buffer, buffer_sz, &config, intf);
        }
    }
}

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
void client_packet_handler(uint8_t *buffer, ssize_t length, struct relay_config *config, std::string &ifname) {
    auto buffer_end = buffer + length;
    const uint8_t *current_position = buffer;
    const uint8_t *prev = NULL;

    auto ether_header = parse_ether_frame(current_position, &current_position);
    auto ip6_header = parse_ip6_hdr(current_position, &current_position);

    prev = current_position;
    if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) {
        const struct ip6_ext *ext_header;
        do {
            ext_header = (const struct ip6_ext *)current_position;
            current_position += ext_header->ip6e_len;
            if((current_position == prev) ||
               (current_position + sizeof(*ext_header) >= buffer_end)) {
                return;
            }
            prev = current_position;
        }
        while (ext_header->ip6e_nxt != IPPROTO_UDP);
    }

    auto udp_header = parse_udp(current_position, &current_position);
    uint16_t udp_len = ntohs(udp_header->len);
    if (udp_len < sizeof(struct udphdr) || (current_position - sizeof(struct udphdr) + udp_len) != buffer_end) {
        syslog(LOG_WARNING, "Invalid UDP header length from %s\n", ifname.c_str());
        return;
    }

    auto msg = parse_dhcpv6_hdr(current_position);
    // RFC3315 only
    if (msg->msg_type < DHCPv6_MESSAGE_TYPE_SOLICIT || msg->msg_type > DHCPv6_MESSAGE_TYPE_RELAY_REPL) {
        increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_UNKNOWN);
        syslog(LOG_WARNING, "Unknown DHCPv6 message type %d from %s\n", msg->msg_type, ifname.c_str());
        return;
    }

    switch (msg->msg_type) {
        case DHCPv6_MESSAGE_TYPE_RELAY_FORW:
        {
            relay_relay_forw(current_position, ntohs(udp_header->len) - sizeof(udphdr), ip6_header, config);
            break;
        }
        case DHCPv6_MESSAGE_TYPE_SOLICIT:
        case DHCPv6_MESSAGE_TYPE_REQUEST: 
        case DHCPv6_MESSAGE_TYPE_CONFIRM:
        case DHCPv6_MESSAGE_TYPE_RENEW:
        case DHCPv6_MESSAGE_TYPE_REBIND:
        case DHCPv6_MESSAGE_TYPE_RELEASE:
        case DHCPv6_MESSAGE_TYPE_DECLINE:
        case DHCPv6_MESSAGE_TYPE_INFORMATION_REQUEST:
        {
            relay_client(current_position, ntohs(udp_header->len) - sizeof(udphdr), ip6_header, ether_header, config);
            break;
        }
        default:
        {
            syslog(LOG_WARNING, "DHCPv6 client message type %d received from %s was not relayed\n", msg->msg_type, ifname.c_str());
            break;
        }
    }
}

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
get_relay_int_from_relay_msg(const uint8_t *msg, int32_t len, std::unordered_map<std::string, relay_config> *vlans) {
    class RelayMsg relay;
    auto result = relay.UnmarshalBinary(msg, len);
    if (!result) {
        syslog(LOG_WARNING, "Relay-reply from loopback socket, option is invalid or contains malformed payload\n");
        return NULL;
    }

    auto opt_value = relay.m_option_list.Get(OPTION_INTERFACE_ID);
    in6_addr address = in6addr_any;
    if (opt_value.empty()) {
        std::memcpy(&address, &relay.m_msg_hdr.link_address, sizeof(in6_addr));
    } else {
        auto interface_id = opt_value.data();
        std::memcpy(&address, interface_id, sizeof(in6_addr));
    }

    // multi-level relay agents
    if (isIPv6Zero(address)) {
        return NULL;
    }

    char ipv6_str[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &address, ipv6_str, INET6_ADDRSTRLEN);
    auto v6_string = std::string(ipv6_str);
    if (addr_vlan_map.find(v6_string) == addr_vlan_map.end()) {
        syslog(LOG_WARNING, "DHCPv6 type %d can't find vlan info from link address %s\n",
               relay.m_msg_hdr.msg_type, ipv6_str);
        return NULL;
    }

    auto vlan_name = addr_vlan_map[v6_string];
    if (vlans->find(vlan_name) == vlans->end()) {
        syslog(LOG_WARNING, "DHCPv6 can't find vlan %s config\n", vlan_name.c_str());
        return NULL;
    }
    return &vlans->find(vlan_name)->second;
}

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
void server_callback_dualtor(evutil_socket_t fd, short event, void *arg) {
    auto vlans = reinterpret_cast<std::unordered_map<std::string, struct relay_config> *>(arg);
    sockaddr_in6 from;
    socklen_t len = sizeof(from);
    int32_t pkts_num = 0;

    while (pkts_num++ < BATCH_SIZE) {
        auto buffer_sz = recvfrom(fd, server_recv_buffer, BUFFER_SIZE, 0, (sockaddr *)&from, &len);
        if (buffer_sz <= 0) {
            if (errno != EAGAIN) {
                syslog(LOG_ERR, "recv: Failed to receive data from server: %s\n", strerror(errno));
            }
            return;
        }

        if (buffer_sz < (int32_t)sizeof(struct dhcpv6_msg)) {
            syslog(LOG_WARNING, "Invalid DHCPv6 packet length %zd, no space for dhcpv6 msg header\n", buffer_sz);
            continue;
        }

        auto msg_type = parse_dhcpv6_hdr(server_recv_buffer)->msg_type;
        if (msg_type != DHCPv6_MESSAGE_TYPE_RELAY_REPL) {
            syslog(LOG_WARNING, "Invalid DHCPv6 message type %d received on loopback interface\n", msg_type);
            continue;
        }
        auto config = get_relay_int_from_relay_msg(server_recv_buffer, buffer_sz, vlans);
        if (!config) {
            syslog(LOG_WARNING, "Invalid DHCPv6 header content on loopback socket, packet will be dropped\n");
            continue;
        }
        auto loopback_str = std::string(loopback);
        increase_counter(config->state_db, loopback_str, msg_type);
        relay_relay_reply(server_recv_buffer, buffer_sz, config);
    }
}

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
void server_callback(evutil_socket_t fd, short event, void *arg) {
    struct relay_config *config = (struct relay_config *)arg;
    sockaddr_in6 from;
    socklen_t len = sizeof(from);
    int32_t pkts_num = 0;

    while (pkts_num++ < BATCH_SIZE) {
        auto buffer_sz = recvfrom(config->gua_sock, server_recv_buffer, BUFFER_SIZE, 0, (sockaddr *)&from, &len);
        if (buffer_sz <= 0) {
            if (errno != EAGAIN) {
                syslog(LOG_ERR, "recv: Failed to receive data from server: %s\n", strerror(errno));
            }
            return;
        }

        if (buffer_sz < (int32_t)sizeof(struct dhcpv6_msg)) {
            syslog(LOG_WARNING, "Invalid DHCPv6 packet length %zd, no space for dhcpv6 msg header\n", buffer_sz);
            continue;
        }

        auto msg_type = parse_dhcpv6_hdr(server_recv_buffer)->msg_type;
        // RFC3315 only
        if (msg_type < DHCPv6_MESSAGE_TYPE_SOLICIT || msg_type > DHCPv6_MESSAGE_TYPE_RELAY_REPL) {
            increase_counter(config->state_db, config->interface, DHCPv6_MESSAGE_TYPE_UNKNOWN);
            syslog(LOG_WARNING, "Unknown DHCPv6 message type %d\n", msg_type);
            continue;
        }

        increase_counter(config->state_db, config->interface, msg_type);
        if (msg_type == DHCPv6_MESSAGE_TYPE_RELAY_REPL) {
            relay_relay_reply(server_recv_buffer, buffer_sz, config);
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
            syslog(LOG_ERR, "Could not create SIGINT libevent signal\n");
            break;
        }

        ev_sigterm = evsignal_new(base, SIGTERM, signal_callback, base);
        if (ev_sigterm == NULL) {
            syslog(LOG_ERR, "Could not create SIGTERM libevent signal\n");
            break;
        }
        rv = 0;
    } while(0);
    return rv;
}

/**
 * @code signal_start();
 *
 * @brief start DHCPv6 Relay libevent base and add signals
 */
int signal_start()
{
    int rv = -1;
    do
    {
        if (evsignal_add(ev_sigint, NULL) != 0) {
            syslog(LOG_ERR, "Could not add SIGINT libevent signal\n");
            break;
        }

        if (evsignal_add(ev_sigterm, NULL) != 0) {
            syslog(LOG_ERR, "Could not add SIGTERM libevent signal\n");
            break;
        }

        if (event_base_dispatch(base) != 0) {
            syslog(LOG_ERR, "Could not start libevent dispatching loop\n");
        }

        rv = 0;
    } while (0);

    return rv;
}

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
void signal_callback(evutil_socket_t fd, short event, void *arg)
{
    syslog(LOG_ALERT, "Received signal: '%s'\n", strsignal(fd));
    if ((fd == SIGTERM) || (fd == SIGINT)) {
        dhcp6relay_stop();
    }
}

/**
 * @code dhcp6relay_stop();
 *
 * @brief stop DHCPv6 Relay libevent loop upon signal
 */
void dhcp6relay_stop()
{
    event_base_loopexit(base, NULL);
}

/**
 * @code                loop_relay(std::unordered_map<relay_config> &vlans);
 * 
 * @brief               main loop: configure sockets, create libevent base, start server listener thread
 *  
 * @param vlans         list of vlans retrieved from config_db
 */
void loop_relay(std::unordered_map<std::string, relay_config> &vlans) {
    std::vector<int> sockets;
    base = event_base_new();
    if(base == NULL) {
        syslog(LOG_ERR, "libevent: Failed to create event base\n");
        exit(EXIT_FAILURE);
    }

    std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
    std::shared_ptr<swss::Table> mStateDbMuxTablePtr = std::make_shared<swss::Table> (
        state_db.get(), "HW_MUX_CABLE_TABLE"
    );

    auto filter = sock_open(&ether_relay_fprog);
    if (filter != -1) {
        sockets.push_back(filter);
        auto event = event_new(base, filter, EV_READ|EV_PERSIST, client_callback,
                               reinterpret_cast<void *>(&vlans));
        if (event == NULL) {
            syslog(LOG_ERR, "libevent: Failed to create client listen event\n");
            exit(EXIT_FAILURE);
        }
        event_add(event, NULL);
        syslog(LOG_INFO, "libevent: Add client listen socket event\n");
    } else {
        syslog(LOG_ERR, "Failed to create client listen socket");
        exit(EXIT_FAILURE);
    }

    int lo_sock = -1;
    if (dual_tor_sock) {
        lo_sock = prepare_lo_socket(loopback);
        if (lo_sock != -1) {
            sockets.push_back(lo_sock);
            auto event = event_new(base, lo_sock, EV_READ|EV_PERSIST, server_callback_dualtor,
                                   reinterpret_cast<void *>(&vlans));
            if (event == NULL) {
                syslog(LOG_ERR, "libevent: Failed to create dualtor loopback listen event\n");
                exit(EXIT_FAILURE);
            }
            event_add(event, NULL);
            syslog(LOG_INFO, "libevent: Add dualtor loopback socket event\n");
        } else{
            syslog(LOG_ERR, "Failed to create dualtor loopback listen socket");
            exit(EXIT_FAILURE);
        }
    }

    for(auto &vlan : vlans) {
        int gua_sock = 0;
        int lla_sock = 0;
        vlan.second.config_db = config_db;
        vlan.second.mux_table = mStateDbMuxTablePtr;
        vlan.second.state_db = state_db;
        vlan.second.mux_key = vlan_member + vlan.second.interface + "|";

        update_vlan_mapping(vlan.first, config_db);

        initialize_counter(vlan.second.state_db, vlan.second.interface);
        
        if (prepare_vlan_sockets(gua_sock, lla_sock, vlan.second) != -1) {
            vlan.second.gua_sock = gua_sock;
            vlan.second.lla_sock = lla_sock;
            vlan.second.lo_sock = lo_sock;

            sockets.push_back(gua_sock);
            sockets.push_back(lla_sock);
            prepare_relay_config(vlan.second, gua_sock, filter);
            if (!dual_tor_sock) {
	            auto event = event_new(base, gua_sock, EV_READ|EV_PERSIST,
                                       server_callback, &(vlan.second));
                if (event == NULL) {
                    syslog(LOG_ERR, "libevent: Failed to create server listen libevent\n");
                }
                event_add(event, NULL);
                syslog(LOG_INFO, "libevent: add server listen socket for %s\n", vlan.first.c_str());
            }
        } else {
            syslog(LOG_ERR, "Failed to create dualtor loopback listen socket");
            exit(EXIT_FAILURE);
        }
    }

    if(signal_init() == 0 && signal_start() == 0) {
        shutdown_relay();
        for(std::size_t i = 0; i < sockets.size(); i++) {
            close(sockets.at(i));
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
    deinitialize_swss();
}
