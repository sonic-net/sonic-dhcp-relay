#pragma once

#include <string>
#include <unordered_map>
#include <boost/thread.hpp>
#include "subscriberstatetable.h"
#include "select.h"
#include "relay.h"

extern bool dual_tor_sock;

struct swssNotification {
    std::unordered_map<std::string, relay_config> vlans;
    swss::SubscriberStateTable *ipHelpersTable;
};

/**
 * @code                void initialize_swss()
 * 
 * @brief               initialize DB tables and start SWSS listening thread
 *
 * @return              none
 */
void initialize_swss(std::unordered_map<std::string, relay_config> &vlans);

/**
 * @code                void deinitialize_swss()
 * 
 * @brief               deinitialize DB interface and join SWSS listening thread
 *
 * @return              none
 */
void deinitialize_swss();

/**
 * @code                void get_dhcp(std::unordered_map<std::string, relay_config> &vlans, swss::SubscriberStateTable *ipHelpersTable,
 *                                    std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief               initialize and get vlan information from DHCP_RELAY
 *
 * @return              none
 */
void get_dhcp(std::unordered_map<std::string, relay_config> &vlans, swss::SubscriberStateTable *ipHelpersTable,
              std::shared_ptr<swss::DBConnector> config_db);

/**
 * @code                    void handleRelayNotification(swss::SubscriberStateTable &ipHelpersTable, std::unordered_map<std::string, relay_config> &vlans,
 *                                                       std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief                   handles DHCPv6 relay configuration change notification
 *
 * @param ipHelpersTable    DHCP table
 * @param vlans             map of vlans/argument config that contains strings of server and option
 *
 * @return                  none
 */
void handleRelayNotification(swss::SubscriberStateTable &ipHelpersTable, std::unordered_map<std::string, relay_config> &vlans,
                             std::shared_ptr<swss::DBConnector> config_db);

/**
 * @code                    void processRelayNotification(std::deque<swss::KeyOpFieldsValuesTuple> &entries, std::unordered_map<std::string, relay_config> &vlans,
 *                                                        std::shared_ptr<swss::DBConnector> config_db)
 * 
 * @brief                   process DHCPv6 relay servers and options configuration change notification
 *
 * @param entries           queue of std::tuple<std::string, std::string, std::vector<FieldValueTuple>> entries in DHCP table
 * @param context           map of vlans/argument config that contains strings of server and option
 *
 * @return                  none
 */
void processRelayNotification(std::deque<swss::KeyOpFieldsValuesTuple> &entries, std::unordered_map<std::string, relay_config> &vlans,
                              std::shared_ptr<swss::DBConnector> config_db);

/**
 * @code                    bool check_is_lla_ready(std::string vlan)
 * 
 * @brief                   Check whether link local address appear in vlan interface
 *
 * @param vlan              string of vlan name
 *
 * @return                  bool value indicates whether lla ready
 */
bool check_is_lla_ready(std::string vlan);

/**
 * @code                build_desired_config(std::shared_ptr<swss::DBConnector> config_db);
 *
 * @brief               read the full DHCP_RELAY table and build the desired per-vlan relay config
 *
 * @param config_db     CONFIG_DB connector used to read DHCP_RELAY and VLAN_INTERFACE
 *
 * @return              desired map of vlan name to relay_config (config fields only)
 */
std::unordered_map<std::string, relay_config> build_desired_config(std::shared_ptr<swss::DBConnector> config_db);

/**
 * @code                start_dhcp_config_monitor(int notify_fd);
 *
 * @brief               start the detached thread that watches CONFIG_DB and publishes desired config
 *
 * @param notify_fd     write end of the pipe used to wake the libevent main loop
 *
 * @return              none
 */
void start_dhcp_config_monitor(int notify_fd);

/**
 * @code                stop_dhcp_config_monitor();
 *
 * @brief               signal the config monitor thread to stop
 *
 * @return              none
 */
void stop_dhcp_config_monitor();

/**
 * @code                fetch_desired_config(std::unordered_map<std::string, relay_config> &out);
 *
 * @brief               copy the latest desired config published by the monitor thread
 *
 * @param out           map populated with the latest desired per-vlan relay config
 *
 * @return              true on success
 */
bool fetch_desired_config(std::unordered_map<std::string, relay_config> &out);
