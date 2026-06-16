#include <sstream>
#include <syslog.h>
#include <algorithm>
#include "config_interface.h"

constexpr auto DEFAULT_TIMEOUT_MSEC = 1000;

bool pollSwssNotifcation = true;
swss::Select swssSelect;

/**
 * @code                void initialize_swss()
 * 
 * @brief               initialize DB tables and start SWSS listening thread
 *
 * @return              none
 */
void initialize_swss(std::unordered_map<std::string, relay_config> &interfaces)
{
    try {
        std::shared_ptr<swss::DBConnector> configDbPtr = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
        swss::SubscriberStateTable ipHelpersTable(configDbPtr.get(), "DHCP_RELAY");
        swssSelect.addSelectable(&ipHelpersTable);
        get_dhcp(interfaces, &ipHelpersTable, false, configDbPtr);
    }
    catch (const std::bad_alloc &e) {
        syslog(LOG_ERR, "Failed allocate memory. Exception details: %s", e.what());
    }
}

/**
*@code      stopSwssNotificationPoll
*
*@brief     stop SWSS listening thread
*
*@return    none
*/
static void stopSwssNotificationPoll() {
    pollSwssNotifcation = false;
};

/**
 * @code                void deinitialize_swss()
 * 
 * @brief               deinitialize DB interface and join SWSS listening thread
 *
 * @return              none
 */
void deinitialize_swss()
{
    stopSwssNotificationPoll();
}

/**

 * @code                void get_dhcp(std::unordered_map<std::string, relay_config> &interfaces, swss::SubscriberStateTable *ipHelpersTable, bool dynamic,
                                      std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief               initialize and get interface table information from DHCP_RELAY
 *
 * @return              none
 */
void get_dhcp(std::unordered_map<std::string, relay_config> &interfaces, swss::SubscriberStateTable *ipHelpersTable, bool dynamic,
              std::shared_ptr<swss::DBConnector> config_db) {
    swss::Selectable *selectable;
    int ret = swssSelect.select(&selectable, DEFAULT_TIMEOUT_MSEC);
    if (ret == swss::Select::ERROR) {
        syslog(LOG_WARNING, "Select: returned ERROR");
        return;
    } else if (ret == swss::Select::TIMEOUT) {
    }
    if (selectable == static_cast<swss::Selectable *> (ipHelpersTable)) {
        if (!dynamic) {
            handleRelayNotification(*ipHelpersTable, interfaces, config_db);
        } else {
            syslog(LOG_WARNING, "relay config changed, "
                   "need restart container to take effect");
        }
    }
}

/**
 * @code                    void handleRelayNotification(swss::SubscriberStateTable &ipHelpersTable, std::unordered_map<std::string, relay_config> &interfaces,
 *                                                       std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief                   handles DHCPv6 relay configuration change notification
 *
 * @param ipHelpersTable    DHCP table
 * @param interfaces        map of interfaces/argument config that contains strings of server and option
 *
 * @return                  none
 */
void handleRelayNotification(swss::SubscriberStateTable &ipHelpersTable, std::unordered_map<std::string, relay_config> &interfaces,
                             std::shared_ptr<swss::DBConnector> config_db)
{
    std::deque<swss::KeyOpFieldsValuesTuple> entries;

    ipHelpersTable.pops(entries);
    processRelayNotification(entries, interfaces, config_db);
}

/**
 * @code                    void processRelayNotification(std::deque<swss::KeyOpFieldsValuesTuple> &entries, std::unordered_map<std::string, relay_config> interfaces,
                                                          std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief                   process DHCPv6 relay servers and options configuration change notification
 *
 * @param entries           queue of std::tuple<std::string, std::string, std::vector<FieldValueTuple>> entries in DHCP table
 * @param interfaces        map of interfaces/argument config that contains strings of server and option
 *
 * @return                  none
 */
void processRelayNotification(std::deque<swss::KeyOpFieldsValuesTuple> &entries, std::unordered_map<std::string, relay_config> &interfaces,
                              std::shared_ptr<swss::DBConnector> config_db)
{
    std::vector<std::string> servers;
    bool option_79_default = true;
    bool interface_id_default = false;

    if (dual_tor_sock) {
        interface_id_default = true;
    }

    for (auto &entry: entries) {
        std::string interface_name = kfvKey(entry);
        std::string operation = kfvOp(entry);
        std::vector<swss::FieldValueTuple> fieldValues = kfvFieldsValues(entry);

        // Handle DELETE operation
        if (operation == "DEL") {
            syslog(LOG_INFO, "Removing DHCPv6 relay config for %s\n", interface_name.c_str());

            // Remove from interface_map
            remove_interface_mapping(interface_name, config_db);

            // Remove from interfaces map
            auto it = interfaces.find(interface_name);
            if (it != interfaces.end()) {
                interfaces.erase(it);
                syslog(LOG_INFO, "Removed %s from relay config map\n", interface_name.c_str());
            }
            continue;
        }

        // Handle SET operation
        bool has_ipv6_address = false;

        // Check both VLAN_INTERFACE and INTERFACE tables for IPv6 addresses
        std::string match_pattern = "VLAN_INTERFACE|" + interface_name + "|*";
        auto keys = config_db->keys(match_pattern);

        // Also check INTERFACE table (for physical ports) and merge results
        match_pattern = "INTERFACE|" + interface_name + "|*";
        auto interface_keys = config_db->keys(match_pattern);

        keys.insert(keys.end(), interface_keys.begin(), interface_keys.end());

        for (const auto &itr : keys) {
            auto found = itr.find_last_of('|');
            if (found == std::string::npos) {
                syslog(LOG_WARNING, "%s doesn't exist in VLAN_INTERFACE or INTERFACE table, skip it", interface_name.c_str());
                continue;
            }
            std::string ip_address = itr.substr(found + 1);
            if (ip_address.find(":") != std::string::npos) {
                has_ipv6_address = true;
                break;
            }
        }

        if (!has_ipv6_address) {
            syslog(LOG_WARNING, "%s doesn't have IPv6 address configured, skip it", interface_name.c_str());
            continue;
        }

        relay_config intf;
        intf.is_option_79 = option_79_default;
        intf.is_interface_id = interface_id_default;
        intf.interface = interface_name;
        intf.mux_key = "";
        intf.state_db = nullptr;
        intf.is_lla_ready = false;
        for (auto &fieldValue: fieldValues) {
            std::string f = fvField(fieldValue);
            std::string v = fvValue(fieldValue);
            if(f == "dhcpv6_servers") {
                std::stringstream ss(v);
                while (ss.good()) {
                    std::string substr;
                    getline(ss, substr, ',');
                    intf.servers.push_back(substr);
                }
                syslog(LOG_DEBUG, "key: %s, Operation: %s, f: %s, v: %s", interface_name.c_str(), operation.c_str(), f.c_str(), v.c_str());
            }
            if(f == "dhcpv6_option|rfc6939_support" && v == "false") {
                intf.is_option_79 = false;
            }
            if(f == "dhcpv6_option|interface_id" && v == "true") { // interface-id is off by default on non-Dual-ToR, unless specified in config db
                intf.is_interface_id = true;
            }
        }
        if (intf.servers.empty()) {
            syslog(LOG_WARNING, "No servers found for interface %s, skipping configuration.", interface_name.c_str());
            continue;
        }
        syslog(LOG_INFO, "add %s relay config, option79 %s interface-id %s\n", interface_name.c_str(),
               intf.is_option_79 ? "enable" : "disable", intf.is_interface_id ? "enable" : "disable");
        interfaces[interface_name] = intf;

        // Update interface_map for this interface
        update_interface_mapping(interface_name, config_db);
    }
}

/**
 * @code                    bool check_is_lla_ready(std::string interface)
 * 
 * @brief                   Check whether link local address appear in an interface
 *
 * @param interface         string of interface name
 *
 * @return                  bool value indicates whether lla ready
 */
bool check_is_lla_ready(std::string interface) {
    const std::string cmd = "ip -6 addr show " + interface + " scope link 2> /dev/null";
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        if (!result.empty()) {
            return true;
        }
    }
    return false;
}
