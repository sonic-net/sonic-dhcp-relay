
#include "dhcp4relay_mgr.h"

#include <algorithm>
#include <sstream>
constexpr auto DEFAULT_TIMEOUT_MSEC = 1000;

static std::unordered_map<std::string, relay_config> vlans_copy;

#ifdef UNIT_TEST
using namespace swss;
#endif

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
    swss::SubscriberStateTable config_db_relaymgr_table(config_db_ptr.get(), "DHCPV4_RELAY");
    swss::SubscriberStateTable config_db_interface_table(config_db_ptr.get(), "INTERFACE");
    swss::SubscriberStateTable config_db_loopback_table(config_db_ptr.get(), "LOOPBACK_INTERFACE");
    swss::SubscriberStateTable config_db_portchannel_table(config_db_ptr.get(), "PORTCHANNEL_INTERFACE");
    swss::SubscriberStateTable config_db_device_metadata_table(config_db_ptr.get(), "DEVICE_METADATA");

    std::deque<swss::KeyOpFieldsValuesTuple> entries;
    swss::Select swss_select;
    swss_select.addSelectable(&config_db_relaymgr_table);
    swss_select.addSelectable(&config_db_interface_table);
    swss_select.addSelectable(&config_db_loopback_table);
    swss_select.addSelectable(&config_db_portchannel_table);
    swss_select.addSelectable(&config_db_device_metadata_table);

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

        if (selectable == static_cast<swss::Selectable *>(&config_db_relaymgr_table)) {
            config_db_relaymgr_table.pops(entries);
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
        } else if (selectable == static_cast<swss::Selectable *>(&config_db_device_metadata_table)) {
            config_db_device_metadata_table.pops(entries);
            process_device_metadata_notification(entries);
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
    // If there is no DHCPv4 Relay config, then no need to send event for metadata update.
    if (vlans_copy.empty()) {
        return;
    }

    for (auto &entry : entries) {
        std::string key = kfvKey(entry);
        std::vector<swss::FieldValueTuple> field_values = kfvFieldsValues(entry);

        if (key != "localhost") {
            continue;
        }

        relay_config *device_data = nullptr;
        try {
            device_data = new relay_config();
        } catch (const std::bad_alloc &e) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Memory allocation failed: %s", e.what());
            return;
        }

        for (auto &field : field_values) {
            std::string f = fvField(field);
            std::string v = fvValue(field);

            if (f == "hostname") {
                device_data->hostname = v;
            } else if (f == "mac") {
                std::array<uint8_t, MAC_ADDR_LEN> host_mac_addr;
                string_to_mac_addr(v, host_mac_addr);
                std::copy(host_mac_addr.begin(), host_mac_addr.end(), device_data->host_mac_addr);
            }
        }

        // Sending sonic as default hostname if it is not present in metadata
        if (device_data->hostname.length() == 0) {
            device_data->hostname = "sonic";
        }

        event_config metadata_event;
        metadata_event.type = DHCPv4_RELAY_METADATA_UPDATE;
        metadata_event.msg = static_cast<void *>(device_data);
        // Write event to config pipe
        if (write(config_pipe[1], &metadata_event, sizeof(metadata_event)) == -1) {
            syslog(LOG_ERR, "[DHCPV4_RELAY] Failed to write metadata update event to pipe: %s", strerror(errno));
            delete device_data;
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

            // Updating the vrf value with default if vrf is not configured.
            if (relay_msg->vrf.length() == 0) {
                relay_msg->vrf = "default";
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

DHCPMgr::~DHCPMgr() {
    stop_thread = true;
}
