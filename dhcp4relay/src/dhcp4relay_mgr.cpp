#include "dhcp4relay_mgr.h"

#include <algorithm>
#include <sstream>
constexpr auto DEFAULT_TIMEOUT_MSEC = 1000;

std::unordered_map<std::string, relay_config> vlans_copy;

#ifdef UNIT_TEST
using namespace swss;
#endif

std::string host_mac_addr;
std::string hostname = "sonic";
uint32_t deployment_id;
bool is_dualTor = false;

bool feature_dhcp_server_enabled = false;
std::shared_ptr<swss::SubscriberStateTable> config_db_dhcp_server_ipv4_ptr = NULL;
std::shared_ptr<swss::SubscriberStateTable> state_db_dhcp_server_ipv4_ip_ptr = NULL;
std::shared_ptr<swss::SubscriberStateTable> config_db_relaymgr_table_ptr = NULL;
std::string global_dhcp_server_ip;
/**
 * @brief Initializes the configuration listener for the DHCP manager.
 *
 * This function starts a new detached thread that listens for SWSS (Switch State Service)
 * notifications by invoking the handle_swss_notification method. It also sets the stop_thread
 * flag to false to indicate that the listener thread should be running.
 *
 * @note The spawned thread is detached, so it will run independently of the main thread.
 */
void DHCPMgr::initialize_config_listner() {
    stop_thread = false;
    std::thread m_swss_thread(&DHCPMgr::handle_swss_notification, this);
    m_swss_thread.detach();
}

/**
 * @brief Handles SWSS (Sonic Warehouse State Service) notifications for DHCPv4 relay manager.
 *
 * This method listens for configuration changes in various tables within the CONFIG_DB,
 * such as DHCPV4_RELAY, INTERFACE, LOOPBACK_INTERFACE, PORTCHANNEL_INTERFACE, and DEVICE_METADATA.
 * It uses a select loop to wait for notifications from these tables and processes them accordingly.
 *
 * The function continues to run until the `stop_thread` flag is set. For each notification,
 * it determines the source table and invokes the appropriate handler to process the entries.
 * Errors and unknown return values from the select operation are logged.
 *
 * Tables monitored:
 * - DHCPV4_RELAY: Triggers relay notification processing.
 * - INTERFACE, LOOPBACK_INTERFACE, PORTCHANNEL_INTERFACE: Triggers interface notification processing.
 * - DEVICE_METADATA: Triggers device metadata notification processing.
 *
 * @note This function is intended to be run in a dedicated thread.
 */
void DHCPMgr::handle_swss_notification() {
    std::shared_ptr<swss::DBConnector> config_db_ptr = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
    std::shared_ptr<swss::DBConnector> state_db_ptr = std::make_shared<swss::DBConnector>("STATE_DB", 0);
    config_db_relaymgr_table_ptr = std::make_shared<swss::SubscriberStateTable>(config_db_ptr.get(), "DHCPV4_RELAY");
    swss::SubscriberStateTable config_db_interface_table(config_db_ptr.get(), "INTERFACE");
    swss::SubscriberStateTable config_db_loopback_table(config_db_ptr.get(), "LOOPBACK_INTERFACE");
    swss::SubscriberStateTable config_db_portchannel_table(config_db_ptr.get(), "PORTCHANNEL_INTERFACE");
    swss::SubscriberStateTable config_db_device_metadata_table(config_db_ptr.get(), "DEVICE_METADATA");
    swss::SubscriberStateTable config_db_vlan_member_table(config_db_ptr.get(), "VLAN_MEMBER");
    swss::SubscriberStateTable config_db_vlan_interface_table(config_db_ptr.get(), "VLAN_INTERFACE");
    swss::SubscriberStateTable config_db_feature_table(config_db_ptr.get(), "FEATURE");
    swss::SubscriberStateTable config_db_vlan_table(config_db_ptr.get(), "VLAN");
    config_db_dhcp_server_ipv4_ptr = std::make_shared<swss::SubscriberStateTable>(config_db_ptr.get(), "DHCP_SERVER_IPV4");
    state_db_dhcp_server_ipv4_ip_ptr = std::make_shared<swss::SubscriberStateTable>(state_db_ptr.get(), "DHCP_SERVER_IPV4_SERVER_IP");

    std::deque<swss::KeyOpFieldsValuesTuple> entries;
    swss::Select swss_select;
    swss_select.addSelectable(config_db_relaymgr_table_ptr.get());
    swss_select.addSelectable(&config_db_interface_table);
    swss_select.addSelectable(&config_db_loopback_table);
    swss_select.addSelectable(&config_db_portchannel_table);
    swss_select.addSelectable(&config_db_device_metadata_table);
    swss_select.addSelectable(&config_db_vlan_member_table);
    swss_select.addSelectable(&config_db_vlan_interface_table);
    swss_select.addSelectable(&config_db_feature_table);
    swss_select.addSelectable(&config_db_vlan_table);
    swss_select.addSelectable(config_db_dhcp_server_ipv4_ptr.get());
    swss_select.addSelectable(state_db_dhcp_server_ipv4_ip_ptr.get());

    while (!stop_thread) {
        swss::Selectable *selectable;
        int ret = swss_select.select(&selectable, DEFAULT_TIMEOUT_MSEC);

        if (ret == swss::Select::ERROR) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Error had been returned in select");
            continue;
        } else if (ret == swss::Select::TIMEOUT) {
            continue;
        } else if (ret != swss::Select::OBJECT) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Unknown return value from Select: %d", ret);
            continue;
        }

	if (!feature_dhcp_server_enabled) {
            if (config_db_relaymgr_table_ptr && selectable == config_db_relaymgr_table_ptr.get()) {
                config_db_relaymgr_table_ptr->pops(entries);
                process_relay_notification(entries);
            } else if (selectable == static_cast<swss::Selectable *>(&config_db_interface_table)) {
                config_db_interface_table.pops(entries);
                process_interface_notification(entries);
            } else if (selectable == static_cast<swss::Selectable *>(&config_db_loopback_table)) {
                config_db_loopback_table.pops(entries);
                process_interface_notification(entries);
            } else if (selectable == static_cast<swss::Selectable *>(&config_db_portchannel_table)) {
                config_db_portchannel_table.pops(entries);
                process_interface_notification(entries);
	    }
	} else {
            if (config_db_dhcp_server_ipv4_ptr && selectable == config_db_dhcp_server_ipv4_ptr.get()) {
                config_db_dhcp_server_ipv4_ptr->pops(entries);
                process_dhcp_server_ipv4_notification(entries);
            } else if (state_db_dhcp_server_ipv4_ip_ptr && selectable == state_db_dhcp_server_ipv4_ip_ptr.get()) {
                state_db_dhcp_server_ipv4_ip_ptr->pops(entries);
                process_dhcp_server_ipv4_ip_notification(entries, swss_select, config_db_ptr);
	    }
	}
        
	if (selectable == static_cast<swss::Selectable *>(&config_db_device_metadata_table)) {
            config_db_device_metadata_table.pops(entries);
            process_device_metadata_notification(entries);
        } else if (selectable == static_cast<swss::Selectable *>(&config_db_vlan_member_table)) {
            config_db_vlan_member_table.pops(entries);
            process_vlan_member_notification(entries);
        } else if (selectable == static_cast<swss::Selectable *>(&config_db_vlan_interface_table)) {
            config_db_vlan_interface_table.pops(entries);
            process_vlan_interface_notification(entries);
        } else if (selectable == static_cast<swss::Selectable *>(&config_db_feature_table)) {
            config_db_feature_table.pops(entries);
            process_feature_notification(entries, swss_select, config_db_ptr, state_db_ptr);
        } else if (selectable == static_cast<swss::Selectable *>(&config_db_vlan_table)) {
            config_db_vlan_table.pops(entries);
            process_vlan_notification(entries);
	}
    }
}

/**
 * @brief Processes device metadata notifications and sends metadata update events if necessary.
 *
 * This function iterates over a deque of device metadata entries, checks for relevant updates,
 * and sends a metadata update event through a configuration pipe if the entry corresponds to "localhost".
 * It extracts fields such as hostname and MAC address from the metadata, constructs a relay_config object,
 * and ensures a default hostname ("sonic") is set if not present. If memory allocation fails or writing
 * to the pipe fails, appropriate error messages are logged.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple containing device metadata notifications.
 */
void DHCPMgr::process_device_metadata_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
    for (auto &entry : entries) {
        std::string key = kfvKey(entry);
        std::vector<swss::FieldValueTuple> field_values = kfvFieldsValues(entry);
        std::string operation = kfvOp(entry);

        if (key != "localhost") {
            continue;
        }
        bool subtype_found = false;
        bool send_dualTor_event = false;
        std::string subtype_value;

        for (auto &field : field_values) {
            std::string f = fvField(field);
            std::string v = fvValue(field);

            if (f == "hostname") {
                hostname = v;
            } else if (f == "mac") {
                std::transform(v.begin(), v.end(), v.begin(), ::tolower);
                host_mac_addr = v;
            } else if (f == "deployment_id") {
                deployment_id = static_cast<uint32_t>(std::stoul(v));
            } else if (f == "subtype") {
                subtype_found = true;
                subtype_value = v;
            }

            // Handle is_dualToR logic
            if (subtype_found && subtype_value == "DualToR") {
                is_dualTor = true;
                send_dualTor_event = true;
            } else if (is_dualTor) {
                // Covers both 'subtype' deleted and any value other than "DualToR"
                is_dualTor = false;
                send_dualTor_event = true;
            }

            if (send_dualTor_event) {
                relay_config *relay_msg = nullptr;
                try {
                    relay_msg = new relay_config();
                } catch (const std::bad_alloc &e) {
                    syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
                    return;
                }

                if (is_dualTor) {
                   relay_msg->is_add = true;
                } else {
                   relay_msg->is_add = false;
                }

                event_config event;
                event.type = DHCPv4_RELAY_DUAL_TOR_UPDATE;
                event.msg = static_cast<void *>(relay_msg);
                // Write the pointer address to the pipe
                if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                    syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to write to config update pipe: %s", strerror(errno));
                    delete relay_msg;
                }
	    }
        }
        /* Re-set hostname to default value if hostname is deleted */
        if (hostname.length() == 0) {
            hostname = "sonic";
        }
    }
}

/**
 * @brief Processes interface notifications and updates DHCP relay configuration accordingly.
 *
 * This method iterates over a deque of interface notification entries, each containing
 * a key, operation, and associated values. For each entry, it parses the interface name
 * and IP address, checks if the interface is configured as a DHCP relay source interface,
 * and prepares a relay configuration update event. Depending on the operation ("SET" or "DEL"),
 * it sets up the relay configuration to add or remove the interface. The configuration update
 * event is then written to a pipe for further processing.
 *
 * Memory allocation failures and invalid IP addresses are logged as errors.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing interface notifications.
 */
void DHCPMgr::process_interface_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
    for (auto &entry : entries) {
        std::string key = kfvKey(entry);
        std::string operation = kfvOp(entry);

        size_t found = key.find("|");

        std::string intf_name;
        std::string ip_with_mask;
        std::string ip;
        if (found != std::string::npos) {
            intf_name = key.substr(0, found);
            ip_with_mask = key.substr(found + 1);
            ip = ip_with_mask.substr(0, ip_with_mask.find('/'));
        } else {
            continue;
        }

        // Check the source interface is configured in dhcp relay config.
        for (auto &vlan : vlans_copy) {
            if (vlan.second.source_interface == intf_name) {
                relay_config *relay_msg = nullptr;
                try {
                    relay_msg = new relay_config();
                } catch (const std::bad_alloc &e) {
                    syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
                    return;
                }

                relay_msg->vlan = vlan.second.vlan;
                if (operation == "SET") {
                    relay_msg->is_add = true;
                    if (inet_pton(AF_INET, ip.c_str(), &relay_msg->src_intf_sel_addr.sin_addr) != 1) {
                        syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid IP address");
                        delete relay_msg;
                        return;
                    }

                    relay_msg->src_intf_sel_addr.sin_family = AF_INET;
                } else if (operation == "DEL") {
                    relay_msg->is_add = false;
                }

                event_config event;
                event.type = DHCPv4_RELAY_INTERFACE_UPDATE;
                event.msg = static_cast<void *>(relay_msg);
                // Write the pointer address to the pipe
                if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                    syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to write to config update pipe: %s", strerror(errno));
                    delete relay_msg;
                }
            }
        }
    }
}

/**
 * @brief Processes a batch of relay configuration notifications for DHCPv4 relay.
 *
 * This method iterates over a deque of relay configuration entries, parses each entry,
 * and updates the internal VLAN relay configuration cache accordingly. For "SET" operations,
 * it creates or updates the relay configuration for the specified VLAN, parsing relevant fields
 * such as DHCPv4 servers, VRF, source interface, and various relay options. For "DEL" operations,
 * it removes the relay configuration for the specified VLAN from the cache.
 *
 * After processing each entry, it constructs an event containing the updated relay configuration
 * and writes it to a configuration update pipe for further handling. The method also logs
 * relevant information and errors using syslog.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing relay configuration notifications.
 */
void DHCPMgr::process_relay_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
    for (auto &entry : entries) {
        std::string vlan = kfvKey(entry);
        std::string operation = kfvOp(entry);
        std::vector<swss::FieldValueTuple> field_values = kfvFieldsValues(entry);
        relay_config *relay_msg = nullptr;
        try {
            relay_msg = new relay_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }

        relay_msg->vlan = vlan;

        if (operation == "SET") {
            relay_msg->is_add = true;
            for (auto &field_value : field_values) {
                std::string f = fvField(field_value);
                std::string v = fvValue(field_value);
                if (f == "dhcpv4_servers") {
                    std::stringstream ss(v);
                    while (ss.good()) {
                        std::string substr;
                        getline(ss, substr, ',');
                        relay_msg->servers.push_back(substr);
                    }
                } else if (f == "server_vrf") {
                    relay_msg->vrf = v;
                } else if (f == "source_interface") {
                    relay_msg->source_interface = v;
                } else if (f == "link_selection") {
                    relay_msg->link_selection_opt = v;
                } else if (f == "server_id_override") {
                    relay_msg->server_id_override_opt = v;
                } else if (f == "vrf_selection") {
                    relay_msg->vrf_selection_opt = v;
                } else if (f == "agent_relay_mode") {
                    relay_msg->agent_relay_mode = v;
                }
                syslog(LOG_DEBUG, "[DHCPV4_RELAY] key: %s, Operation: %s, f: %s, v: %s", vlan.c_str(), operation.c_str(), f.c_str(), v.c_str());
            }

            // Updating vrf value with client VRF if server vrf is not configured.
            if (relay_msg->vrf.length() == 0) {
                std::string value;
                std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
                std::shared_ptr<swss::Table> vlan_intf_tbl = std::make_shared<swss::Table>(config_db.get(), CFG_VLAN_INTF_TABLE_NAME);
                vlan_intf_tbl->hget(vlan, "vrf_name", value);
                if (value.size() <= 0) {
                    relay_msg->vrf = "default";
                } else {
                    relay_msg->vrf = value;
                }
            }

            // Update the vlan cache entry
            vlans_copy[relay_msg->vlan] = *relay_msg;
        } else if (operation == "DEL") {
            syslog(LOG_INFO, "[DHCPV4_RELAY] Received DELETE operation for VLAN %s", vlan.c_str());
            relay_msg->is_add = false;
            // Remove the vlan cache entry
            vlans_copy.erase(relay_msg->vlan);
        }

        if (relay_msg->servers.empty() && operation != "DEL") {
            syslog(LOG_WARNING, "[DHCPV4_RELAY] No servers found for VLAN %s, skipping configuration.", vlan.c_str());
            continue;
        }
        syslog(LOG_INFO, "[DHCPV4_RELAY] %s %s relay config\n", operation.c_str(), vlan.c_str());

        event_config event;
        event.type = DHCPv4_RELAY_CONFIG_UPDATE;
        event.msg = static_cast<void *>(relay_msg);

        // Write the pointer address to the pipe
        if (write(config_pipe[1], &event, sizeof(event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to write to config update pipe: %s", strerror(errno));
            delete relay_msg;
        }
    }
}

/**
 * @brief Processes the feature table updates to configure the dhcp_server enabled/disbaled.
 *
 * This method iterates over a deque of relay configuration entries, parses each entry,
 * if the entry is for 'dhcp_server' then based on the 'state' value it will process the entry.
 * If the "state" is "enable" then it will send the delete event to main thread to remove all the 
 * existing dhcp_relay config and then restart the listeners for dhcp_server related tables.
 * If the "state" is "disable" then it will send the delete event to main thread to remove all the
 * auto configured dhcp_server config and then restart the listeners dhcp_relay related table.
 *
 * The method will handle the clean up for the vlan cache entries and  also logs relevant information 
 * and errors using syslog.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing feature table notifications.
 *        config_db_ptr It represents the pointer for the CONFIG_DB
 *        state_db_ptr It represents the pointer for the STATE_DB
 */
void DHCPMgr::process_feature_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries,
                                           swss::Select &select, std::shared_ptr<swss::DBConnector> config_db_ptr,
					   std::shared_ptr<swss::DBConnector> state_db_ptr) {
    for (auto &entry : entries) {
        if (kfvKey(entry) != "dhcp_server") {
	    continue;
	}

        std::string state;
        for (auto &field : kfvFieldsValues(entry)) {
            if (fvField(field) == "state") {
                state = fvValue(field);
                break;
            }
        }

        if (state == "enabled" && !feature_dhcp_server_enabled) {
            //Delete the existing vlan configs in main thread
	    event_config event;
            event.type = DHCPv4_SERVER_FEATURE_UPDATE;

            if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send delete event for dhcp_server feature update");
		return;
            }
            vlans_copy.clear();
            feature_dhcp_server_enabled = true;

	    if (config_db_dhcp_server_ipv4_ptr) {
                select.removeSelectable(config_db_dhcp_server_ipv4_ptr.get());
            }
            if (state_db_dhcp_server_ipv4_ip_ptr) {
               select.removeSelectable(state_db_dhcp_server_ipv4_ip_ptr.get());
            }

            config_db_dhcp_server_ipv4_ptr = std::make_shared<swss::SubscriberStateTable>(config_db_ptr.get(), "DHCP_SERVER_IPV4");
            state_db_dhcp_server_ipv4_ip_ptr = std::make_shared<swss::SubscriberStateTable>(state_db_ptr.get(), "DHCP_SERVER_IPV4_SERVER_IP");

            select.addSelectable(config_db_dhcp_server_ipv4_ptr.get());
            select.addSelectable(state_db_dhcp_server_ipv4_ip_ptr.get());
        } else if (state == "disabled" && feature_dhcp_server_enabled) {
            syslog(LOG_INFO, "[DHCPV4_RELAY] Disabling DHCP server auto-config mode and cleaning up.");
            feature_dhcp_server_enabled = false;
            global_dhcp_server_ip.clear();
	    vlans_copy.clear();
	    //Delete the old auto generated relay config in main thread
	    event_config event;
            event.type = DHCPv4_SERVER_FEATURE_UPDATE;

            if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send delete event for dhcp_server feature update");
		return;
            }

	    //re-add the dhcp relay listeners
	    if (config_db_relaymgr_table_ptr) {
                select.removeSelectable(config_db_relaymgr_table_ptr.get());
            }
            config_db_relaymgr_table_ptr = std::make_shared<swss::SubscriberStateTable>(config_db_ptr.get(), "DHCPV4_RELAY");
            select.addSelectable(config_db_relaymgr_table_ptr.get());
        }
    }
}

/**
 * @brief Processes the dhcp_server_ip entry and stores the IP in the global parameter.
 *
 * This method iterates over a deque of dhcp_server_ip configuration entries, parses each entry,
 * if the entry is for 'eth0' then only it will process the entry.
 * If the operation is "SET" then it will stores the IP in global parameter and restart the dhcp_server
 * related as it is the new configuration of the IP.
 * If the operation is "DEL" then it will send the delete event to main thread to remove all the
 * auto configured dhcp_server config, as without IP, the relay config can't be formed.
 *
 * The method will handle the clean up for the vlan cache entries and  also logs relevant information 
 * and errors using syslog.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing dhcp_server_ip table notifications.
 *        config_db_ptr It represents the pointer for the CONFIG_DB
 */
void DHCPMgr::process_dhcp_server_ipv4_ip_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries,
		                                       swss::Select &select, std::shared_ptr<swss::DBConnector> config_db_ptr) {
   bool is_modify = false;

   for (auto &entry : entries) {
        std::string server_intf = kfvKey(entry);
        std::string operation = kfvOp(entry);
 
	if (server_intf != "eth0") {
            continue;
        }

        if (operation == "SET") {
            std::string server_ip;
            for (auto &fv : kfvFieldsValues(entry)) {
                  if (fvField(fv) == "ip") {
                      server_ip = fvValue(fv);
                      break;
                  }
            }
	    if (server_ip.empty()) {
		  syslog(LOG_ERR, "[DHCPV4_RELAY] dhcp_server IP is not present in state DB");
		  return;
            }
	    //modification case
            if (!global_dhcp_server_ip.empty() && (global_dhcp_server_ip != server_ip)) {
		event_config event;
                event.type = DHCPv4_SERVER_IP_UPDATE;

		if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                    syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send delete event for dhcp_server IP update");
		    return;
                }
		is_modify = true;
	    }
	    global_dhcp_server_ip = server_ip;
	    //Since the server IP see newly added, restart the listener for the dhcp_server config.
	    if (!is_modify) {
	       syslog(LOG_INFO, "[DHCPV4_RELAY] Restarting the dhcp_server listener");
               if (config_db_dhcp_server_ipv4_ptr) {
                   select.removeSelectable(config_db_dhcp_server_ipv4_ptr.get());
               }
               config_db_dhcp_server_ipv4_ptr = std::make_shared<swss::SubscriberStateTable>(config_db_ptr.get(), "DHCP_SERVER_IPV4");
               select.addSelectable(config_db_dhcp_server_ipv4_ptr.get());
	    }
        } else {
           //DHCP server IP deletion case, need to remove the existing configs in main thread
            event_config event;
            event.type = DHCPv4_SERVER_IP_DELETE;

            if (write(config_pipe[1], &event, sizeof(event)) == -1) {
                syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send delete event for dhcp_server IP delete");
		return;
            }
	    global_dhcp_server_ip.clear();
	    vlans_copy.clear();
	}
    }
}

void DHCPMgr::process_vlan_member_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
     for (auto &entry : entries) {
        std::string key = kfvKey(entry);
        std::string operation = kfvOp(entry);

         size_t pos = key.find('|');
         if (pos == std::string::npos) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Invalid string format");
            return;
         }

         std::string vlan = key.substr(0, pos);
         std::string interface = key.substr(pos + 1);

        //If the vlan is not configured in DHCPV4 table then skip the entry.
        if (vlans_copy.find(vlan) == vlans_copy.end()) {
            continue;
        }

        vlan_member_config *msg = nullptr;
        try {
            msg = new vlan_member_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }

	msg->vlan = vlan;
        msg->interface = interface;

        if (operation == "SET") {
           msg->is_add = true;
        } else {
           msg->is_add = false;
        }

        event_config event;
	event.type = DHCPv4_RELAY_VLAN_MEMBER_UPDATE;
        event.msg = static_cast<void *>(msg);

        if (write(config_pipe[1], &event, sizeof(event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send vlan member update for vlan %s", vlan.c_str());
            delete msg;
        }
     }
}

void DHCPMgr::process_vlan_interface_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
     for (auto &entry : entries) {
        std::string key = kfvKey(entry);

         std::string vlan;
         std::string vrf;
         size_t pos = key.find('|');
         if (pos == std::string::npos) {
             vlan = key;
             vrf = "default";
             for (auto &fv : kfvFieldsValues(entry)) {
                 if (fvField(fv) == "vrf_name") {
                     vrf = fvValue(fv);
                     break;
                 }
            }
         } else {
             vlan = key.substr(0, pos);
         }

        //If the vlan is not configured in DHCPV4 table then skip the entry.
        if (vlans_copy.find(vlan) == vlans_copy.end()) {
            continue;
        }

        vlan_interface_config *msg = nullptr;
        try {
            msg = new vlan_interface_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }
        msg->vlan = vlan;
        msg->vrf = vrf;

        event_config event;
        event.type = DHCPv4_RELAY_VLAN_INTERFACE_UPDATE;
        event.msg = static_cast<void *>(msg);

        if (write(config_pipe[1], &event, sizeof(event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send vlan interface update for vlan %s", vlan.c_str());
            delete msg;
        }

     }
}

/**
 * @brief Processes the dhcp_server table entry to form the dhcp_relay config.
 *
 * This method iterates over a deque of dhcp_server configuration entries, parses each entry,
 * If the operation is "SET" then based on the "state" value it will proceed entry,
 * it will adds the vlan and server IP to for the relay_config and send the event to main thread.
 * If the server IP is not updated then it will get the entry from DB and fill it.
 * related as it is the new configuration of the IP. 
 * If the Vlan is not present in the VLAN table then it will not send the config event to main thread.
 * If the operation is "DEL" then it will send the delete entry event to the main thread.
 *
 * The method will handle the updating the vlan cache entries and  also logs relevant information
 * and errors using syslog.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing dhcp_server table notifications.
 */
void DHCPMgr::process_dhcp_server_ipv4_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
    std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector>("CONFIG_DB", 0);
    swss::Table vlan_tbl(config_db.get(), "VLAN");

    for (auto &entry : entries) {
        std::string vlan = kfvKey(entry);
        std::string operation = kfvOp(entry);

       	relay_config *relay_msg = nullptr;
        try {
            relay_msg = new relay_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }

        relay_msg->vlan = vlan;

        if (operation == "SET") {
            std::string state;
            for (auto &fv : kfvFieldsValues(entry)) {
                 if (fvField(fv) == "state") {
                     state = fvValue(fv);
                     break;
                 }
            }

            if (state == "enabled") {
              if (global_dhcp_server_ip.empty()) {
                  std::shared_ptr<swss::DBConnector> state_db_ptr = std::make_shared<swss::DBConnector>("STATE_DB", 0);
                  swss::Table ip_tbl(state_db_ptr.get(), "DHCP_SERVER_IPV4_SERVER_IP");

                  std::string ip;
                  ip_tbl.hget("eth0", "ip", ip);
                  if (!ip.empty()) {
                     global_dhcp_server_ip = ip;
                     syslog(LOG_INFO, "[DHCPV4_RELAY] Fetched DHCPv4 server IP from STATE_DB: %s", ip.c_str());
                  } else {
                     syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to get DHCPv4 server IP from STATE_DB");
                     continue;
                  }
              }
              relay_msg->is_add = true;
              relay_msg->servers.push_back(global_dhcp_server_ip);
              relay_msg->vrf = "default";
            } else if (state == "disabled") {
		relay_msg->is_add = false; //In case of modify in state field need to delete the entry
	    }
        } else {
	    relay_msg->is_add = false;
	}   

	// Update the vlan cache entry
	if (relay_msg->is_add) {
	    vlans_copy[relay_msg->vlan] = *relay_msg;
	} else {
            vlans_copy.erase(relay_msg->vlan);
	}

	/*Validation to check vlan is present in VLAN table or not */
	std::string value;
        if (!vlan_tbl.hget(vlan, "vlanid", value)) {
            delete relay_msg;
            continue;
        }

	event_config event;
        event.type = DHCPv4_SERVER_RELAY_CONFIG_UPDATE;
        event.msg = static_cast<void *>(relay_msg);

        if (write(config_pipe[1], &event, sizeof(event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send vlan table update for VLAN %s", vlan.c_str());
            delete relay_msg;
        }
    }
}

/**
 * @brief Processes the vlan table entry.
 *
 * This method iterates over a deque of vlan configuration entries, parses each entry,
 * If any dhcp_relay/dhcp_server entry exists in the vlan cache list then based on the
 *  operation "SET" or "DEL" it will send the update event to main thread to process that entry.
 *
 * @param entries A deque of KeyOpFieldsValuesTuple objects representing vlan table notifications.
 */
void DHCPMgr::process_vlan_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries) {
    for (auto &entry : entries) {
        std::string vlan = kfvKey(entry);
        std::string operation = kfvOp(entry);
        
        //If the vlan is not configured in DHCPV4 table then skip the entry.	
	if (vlans_copy.find(vlan) == vlans_copy.end()) {
            continue;
	}

        relay_config *relay_msg = nullptr;
        try {
            relay_msg = new relay_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }

	relay_msg->vlan = vlan;
	
	if (operation == "SET") {
           *relay_msg = vlans_copy[relay_msg->vlan];
           relay_msg->is_add = true;
	} else {
           relay_msg->is_add = false;
        }

        event_config event;
	if (feature_dhcp_server_enabled) {
            event.type = DHCPv4_SERVER_RELAY_CONFIG_UPDATE;
	} else {
            event.type = DHCPv4_RELAY_CONFIG_UPDATE;
	}
        event.msg = static_cast<void *>(relay_msg);

        if (write(config_pipe[1], &event, sizeof(event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to send vlan update event for vlan %s", vlan.c_str());
            delete relay_msg;
        }
    }
}

/**
 * @code                void DHCPMgr::stop_db_updates();
 *
 * @brief               Method to stop thread which will be listening to the DB updates..
 *
 * @return              none
 */

void DHCPMgr::stop_db_updates() {
	stop_thread = true;
}

/**
 * @code                DHCPMgr::~DHCPMgr()
 *
 * @brief               Destructor.
 *
 * @return              none
 */
DHCPMgr::~DHCPMgr() {
    stop_db_updates();
}
