#pragma once

#include <atomic>
#include <boost/thread.hpp>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "dbconnector.h"
#include "dhcp4relay.h"
#include "select.h"
#include "subscriberstatetable.h"
#include "table.h"

class DHCPMgr {
   private:
    std::atomic<bool> stop_thread;

    /* CONFIG_DB key -> kernel netdev name. Populated on SET, consulted on
     * DEL because SubscriberStateTable hands DEL events with no fields. */
    std::unordered_map<std::string, std::string> vxlan_tunnel_map_netdev_cache_;

   public:
    DHCPMgr() : stop_thread(false) {}
    ~DHCPMgr();

    void initialize_config_listener();
    void handle_swss_notification();
    void stop_db_updates();
    void process_relay_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_interface_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_device_metadata_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_vlan_member_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_vlan_interface_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_feature_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries,
		                      swss::Select &select, std::shared_ptr<swss::DBConnector> config_db_ptr,
                                           std::shared_ptr<swss::DBConnector> state_db_ptr);
    void process_dhcp_server_ipv4_ip_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries,
		                      swss::Select &select, std::shared_ptr<swss::DBConnector> config_db_ptr);
    void process_dhcp_server_ipv4_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_vlan_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_port_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_vxlan_tunnel_map_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
};
