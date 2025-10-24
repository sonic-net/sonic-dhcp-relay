#include "dhcp4relay_stats.h"

#include "dbconnector.h"
#include "dhcp4relay.h"
#include "table.h"

using namespace swss;

/* DHCPv4 counter name map */
std::map<int, std::string> counter_map = {
    {DHCPv4_MESSAGE_TYPE_UNKNOWN, "Unknown"},
    {DHCPv4_MESSAGE_TYPE_DISCOVER, "Discover"},
    {DHCPv4_MESSAGE_TYPE_OFFER, "Offer"},
    {DHCPv4_MESSAGE_TYPE_REQUEST, "Request"},
    {DHCPv4_MESSAGE_TYPE_DECLINE, "Decline"},
    {DHCPv4_MESSAGE_TYPE_ACK, "Acknowledge"},
    {DHCPv4_MESSAGE_TYPE_NAK, "NegativeAcknowledge"},
    {DHCPv4_MESSAGE_TYPE_RELEASE, "Release"},
    {DHCPv4_MESSAGE_TYPE_INFORM, "Inform"},
    {DHCPv4_MESSAGE_TYPE_MALFORMED, "Malformed"},
    {DHCPv4_MESSAGE_TYPE_DROP, "Dropped"}};

/**
 * @code                calculate_delta(uint64_t new_value, uint64_t old_value);
 *
 * @brief               Helper function to calculate safe delta with overflow handling.
 *
 * @param new_value     new uint64_t value
 * @param old_value     old uint64_t value
 *
 * @return              delta value
 */
uint64_t calculate_delta(uint64_t new_value, uint64_t old_value) {
    if (new_value >= old_value) {
        return new_value - old_value;
    } else {
        // Handle overflow case
        return (std::numeric_limits<uint64_t>::max() - old_value) + new_value + 1;
    }
}

/**
 * @code                get_counters_data()
 *
 * @brief               GET function to fetch data of private member interfaces_cntr_table
 *
 * @return              std::unordered_map<std::string, DHCPCounters>
 */
std::unordered_map<std::string, DHCPCounters> DHCPCounter_table::get_counters_data() {
    return interfaces_cntr_table;
}

/**
 * @brief Helper function to update RX/TX counters in the DB for a given interface and direction.
 *
 * @param cntr_table Shared pointer to the swss::Table for updating the DB.
 * @param interface Name of the interface.
 * @param direction "RX" or "TX".
 * @param counters_map Reference to the map of counters (either RX or TX).
 */
void update_interface_counters_in_db(
    std::shared_ptr<swss::Table> cntr_table,
    const std::string& interface,
    const std::string& direction,
    const std::unordered_map<std::string, uint64_t> counters_map)
{
    std::vector<swss::FieldValueTuple> existing_fields;
    std::string key = interface + swss::TableBase::getTableSeparator(COUNTERS_DB) + direction;
    cntr_table->get(key, existing_fields);

    std::vector<swss::FieldValueTuple> fields;
    std::unordered_map<std::string, uint64_t> counter_map;

    // Populate existing counters
    for (const auto& field : existing_fields) {
        counter_map[fvField(field)] = std::stoi(fvValue(field));
    }

    // Update with new values
    for (const auto& [type, value] : counters_map) {
        counter_map[type] += value;
        fields.emplace_back(type, std::to_string(counter_map[type]));
    }

    cntr_table->set(key, fields);
}

/**
 * @code                DHCPCounter_table::db_update_loop();
 *
 * @brief               Loop to update dhcp stats to the DB periodically.
 *                      This loop is triggered by a new thread which is responsible to update stats to DB.
 *
 *                      Mutex lock is taken to copy the data locally, before parsing and setting to DB.
 *
 * @return              none
 */
void DHCPCounter_table::db_update_loop() {
    std::shared_ptr<swss::DBConnector> cntrs_db = std::make_shared<swss::DBConnector>("COUNTERS_DB", 0);
    std::shared_ptr<swss::Table> cntr_table = std::make_shared<swss::Table>(
        cntrs_db.get(), COUNTERS_DHCPv4_TABLE);

    while (!stop_thread) {
        std::this_thread::sleep_for(std::chrono::seconds(DHCP_RELAY_DB_UPDATE_TIMER_VAL));

        // Copy the data by taking lock for processing and populating to DB
        std::unordered_map<std::string, DHCPCounters> interfaces_copy;
        {
            std::lock_guard<std::mutex> lock(interfaces_mutex);
            interfaces_copy = interfaces_cntr_table;
        }

        /* These steps are followed before updating to Redis:
           1. Fetch present values from redis - existing _fields
           2. Update counters with 'cache values' + 'existing_fields'
           3. Populate to DB
        */
        for (const auto& [interface, counters] : interfaces_copy) {
            update_interface_counters_in_db(cntr_table, interface, "RX", counters.RX);
            update_interface_counters_in_db(cntr_table, interface, "TX", counters.TX);
        }

        // Update local changes after syncing to Redis
        // We will take the delta values of running data in interfaces_cntr_table
        // and previously copied interfaces_copy values.
        {
            // Taking lock inside a block so that is released automatically
            std::lock_guard<std::mutex> lock(interfaces_mutex);
            for (auto& [interface, counters] : interfaces_cntr_table) {
                for (auto& [type, value] : counters.RX) {
                    value = calculate_delta(value, interfaces_copy[interface].RX[type]);
                }
                for (auto& [type, value] : counters.TX) {
                    value = calculate_delta(value, interfaces_copy[interface].TX[type]);
                }
            }
        }
        syslog(LOG_INFO, "DHCPV4_RELAY: DHCPCounter_table::db_update_loop() : Data Updated to DB \n");
    }
}

/**
 * @code                DHCPCounter_table::start_db_updates();
 *
 * @brief               Method to start thread to update stats to DB periodically.
 *
 * @return              none
 */
void DHCPCounter_table::start_db_updates() {
    db_update_thread = std::thread(&DHCPCounter_table::db_update_loop, this);
}

/**
 * @code                DHCPCounter_table::stop_db_updates();
 *
 * @brief               Method to stop thread which updates stats to DB periodically.
 *
 * @return              none
 */
void DHCPCounter_table::stop_db_updates() {
    stop_thread = true;
    if (db_update_thread.joinable()) {
        db_update_thread.join();
    }
}

/**
 * @code                DHCPCounter_table::initialize_interface(std::string& interface);
 *
 * @brief               Method to initialize counters in DB for a particular interface
 *
 * @param interface     Name of the interface for which RX and TX counters need to be initialized
 *
 * @return              none
 */
void DHCPCounter_table::initialize_interface(const std::string& interface) {
    std::lock_guard<std::mutex> lock(interfaces_mutex);
    DHCPCounters counter;
    for (const auto& type : counter_map) {
        counter.RX[type.second] = 0;
        counter.TX[type.second] = 0;
    }
    interfaces_cntr_table[interface] = counter;
}

/**
 * @code                DHCPCounter_table::increment_counter(const std::string& interface,
 *                                                          const std::string& direction,
 *                                                          int msg_type);
 *
 * @brief               Method to increment counters in DB for a particular interface,
 *                      direction(RX|TX) and dhcp_message_type_t
 *
 * @param interface     Name of the interface for which counters need to be incremented
 *
 * @return              none
 */
void DHCPCounter_table::increment_counter(const std::string& interface,
                                        const std::string& direction,
                                        int msg_type) {
    std::string type = counter_map.find(msg_type)->second;
    // Initialize counters if not present
    if (interfaces_cntr_table.find(interface) == interfaces_cntr_table.end())
        DHCPCounter_table::initialize_interface(interface);

    std::lock_guard<std::mutex> lock(interfaces_mutex);

    if (direction == "RX") {
        interfaces_cntr_table[interface].RX[type]++;
    } else if (direction == "TX") {
        interfaces_cntr_table[interface].TX[type]++;
    }
}

/**
 * @code                DHCPCounter_table::remove_interface(const std::string& interface);
 *
 * @brief               Method to remove counters from global datastructure.
 *
 * @param interface     Name of the interface for which counters need to be removed.
 *
 * @return              none
 */
void DHCPCounter_table::remove_interface(const std::string& interface) {
    std::lock_guard<std::mutex> lock(interfaces_mutex);
    interfaces_cntr_table.erase(interface);
}

/**
 * @code                DHCPCounter_table:~DHCPCounter_table()
 *
 * @brief               Destructor.
 *
 * @return              none
 */
DHCPCounter_table::~DHCPCounter_table() {
    stop_db_updates();
}
