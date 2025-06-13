#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

#include "mock_relay.h"
#include "../src/dhcp4relay_stats.h"

using namespace swss;

// Test fixture
class DHCPCounter_table_test : public ::testing::Test {
protected:
    std::unique_ptr<DHCPCounter_table> counter_table;

    void SetUp() override {
        counter_table = std::make_unique<DHCPCounter_table>();
    }

    void TearDown() override {
        counter_table.reset();
    }
};

// Test the delta calculation function
TEST(Calculate_delta_test, Calculates_delta_correctly) {
    // Normal case
    EXPECT_EQ(calculate_delta(10, 5), 5);

    // Zero delta
    EXPECT_EQ(calculate_delta(5, 5), 0);

    // Handle overflow case
    uint64_t max_val = std::numeric_limits<uint64_t>::max();
    uint64_t old_val = max_val - 5;
    uint64_t new_val = 10;

    EXPECT_EQ(calculate_delta(new_val, old_val), 16);
}

// Test interface initialization
TEST_F(DHCPCounter_table_test, Initialize_interface) {
    const std::string interface = "Ethernet0";

    // Initialize the interface
    counter_table->initialize_interface(interface);

    // Increment counters
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    counter_table->increment_counter(interface, "TX", DHCPv4_MESSAGE_TYPE_OFFER);

    // Verify Incremented counters from table
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 1);
    EXPECT_EQ(interfaces_cntr_table[interface].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_OFFER)->second], 1);

    // If initialization failed, the above would likely crash
    SUCCEED();
}

// Test counter incrementation
TEST_F(DHCPCounter_table_test, Increment_counter) {
    const std::string interface = "Ethernet0";

    // Initialize and increment counters
    counter_table->initialize_interface(interface);

    // Increment RX counter multiple times
    for (int i = 0; i < 5; i++) {
        counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    }

    // Increment TX counter once
    counter_table->increment_counter(interface, "TX", DHCPv4_MESSAGE_TYPE_ACK);

    // Verify Incremented counters from table
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 5);
    EXPECT_EQ(interfaces_cntr_table[interface].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_ACK)->second], 1);

    // Negative case - other counters should NOT have incremented
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_REQUEST)->second], 0);
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_OFFER)->second], 0);
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_ACK)->second], 0);
    EXPECT_EQ(interfaces_cntr_table[interface].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_DECLINE)->second], 0);
    EXPECT_EQ(interfaces_cntr_table[interface].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_INFORM)->second], 0);
   
    SUCCEED();
}

// Test with uninitialized interface
TEST_F(DHCPCounter_table_test, Auto_initialize_interface) {
    const std::string interface = "Ethernet1";

    // Try to increment without explicitly initializing
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);

    // If auto-initialization works, this should succeed
    counter_table->increment_counter(interface, "TX", DHCPv4_MESSAGE_TYPE_ACK);

    // Verify Incremented counters from table
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 1);
    EXPECT_EQ(interfaces_cntr_table[interface].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_ACK)->second], 1);

    SUCCEED();
}

// Test interface removal
TEST_F(DHCPCounter_table_test, Remove_interface) {
    const std::string interface = "Ethernet0";

    // Initialize and increment counters
    counter_table->initialize_interface(interface);
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    
    // Verify Incremented counters from table
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 1);

    // Remove the interface
    counter_table->remove_interface(interface);

    // Now add it again - if removal worked, this should reinitialize from scratch
    // and should not crash
    counter_table->initialize_interface(interface);

    // Increment the same counter and verify
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    // verify counter
    interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interface].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 1);

    SUCCEED();
}

// Test starting and stopping the DB update thread
TEST_F(DHCPCounter_table_test, Start_stop_db_updates) {
    // Start the DB update thread
    counter_table->start_db_updates();

    // Sleep briefly to allow thread to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Stop the thread
    counter_table->stop_db_updates();

    // If the start/stop mechanisms work correctly, this will complete without hanging
    SUCCEED();
}

// Integration test for database update loop
TEST_F(DHCPCounter_table_test, DBUpdate_loop_integration) {
    const std::string interface = "Ethernet0";

    // Initialize and increment counters
    counter_table->initialize_interface(interface);

    // Add some counter increments
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    counter_table->increment_counter(interface, "RX", DHCPv4_MESSAGE_TYPE_REQUEST);
    counter_table->increment_counter(interface, "TX", DHCPv4_MESSAGE_TYPE_OFFER);
    counter_table->increment_counter(interface, "TX", DHCPv4_MESSAGE_TYPE_ACK);

    // Start DB updates
    counter_table->start_db_updates();

    // Let the update thread run briefly (less than the normal interval for test speed)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Stop the updates
    counter_table->stop_db_updates();

    std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
    swss::Table cntr_table(state_db.get(), "DHCPV4_COUNTER_TABLE");
    std::vector<swss::FieldValueTuple> existing_rx_fields;
    std::vector<swss::FieldValueTuple> existing_tx_fields;
    cntr_table.get(interface+"|RX", existing_rx_fields);
    cntr_table.get(interface+"|TX", existing_tx_fields);

    //Verify Incremented Rx fields
    for (const auto& field : existing_rx_fields) {
	if ( (fvField(field)) == "Discover" || (fvField(field)) == "Request") {
	    EXPECT_EQ(std::stoi(fvValue(field)), 1);
	}
    }
    //Verify Incremented Tx fields
    for (const auto& field : existing_tx_fields) {
	if ( (fvField(field)) == "Offer" || (fvField(field)) == "Acknowledge") {
	    EXPECT_EQ(std::stoi(fvValue(field)), 1);
	}
    }

    SUCCEED();
}

// Test for handling multiple interfaces
TEST_F(DHCPCounter_table_test, Multiple_interfaces) {
    const std::vector<std::string> interfaces = {"Ethernet0", "Ethernet1", "Ethernet2"};

    // Initialize multiple interfaces
    for (const auto& intf : interfaces) {
        counter_table->initialize_interface(intf);
    }

    // Increment counters for different interfaces
    counter_table->increment_counter(interfaces[0], "RX", DHCPv4_MESSAGE_TYPE_DISCOVER);
    counter_table->increment_counter(interfaces[1], "RX", DHCPv4_MESSAGE_TYPE_REQUEST);
    counter_table->increment_counter(interfaces[2], "TX", DHCPv4_MESSAGE_TYPE_ACK);

    // Verify Incremented counters from table
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interfaces[0]].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_DISCOVER)->second], 1);
    EXPECT_EQ(interfaces_cntr_table[interfaces[1]].RX[counter_map.find(DHCPv4_MESSAGE_TYPE_REQUEST)->second], 1);
    EXPECT_EQ(interfaces_cntr_table[interfaces[2]].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_ACK)->second], 1);
    
    // Remove one interface
    counter_table->remove_interface(interfaces[1]);

    // Try incrementing the removed interface (should auto-initialize)
    counter_table->increment_counter(interfaces[1], "TX", DHCPv4_MESSAGE_TYPE_OFFER);
    // Verify incremented counter
    interfaces_cntr_table = counter_table->get_counters_data();
    EXPECT_EQ(interfaces_cntr_table[interfaces[1]].TX[counter_map.find(DHCPv4_MESSAGE_TYPE_OFFER)->second], 1);

    SUCCEED();
}
