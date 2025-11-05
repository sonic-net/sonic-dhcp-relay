#pragma once

#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <limits>

#define DHCP_RELAY_DB_UPDATE_TIMER_VAL 30

extern std::map<int, std::string> counter_map;

struct DHCPCounters {
    std::unordered_map<std::string, uint64_t> RX;
    std::unordered_map<std::string, uint64_t> TX;
};

class DHCPCounter_table {
private:
    std::unordered_map<std::string, DHCPCounters> interfaces_cntr_table;
    std::mutex interfaces_mutex;
    std::atomic<bool> stop_thread{false};
    std::thread db_update_thread;

    void db_update_loop();

public:
    void start_db_updates();
    void stop_db_updates();
    void initialize_interface(const std::string& interface);
    void increment_counter(const std::string& interface, const std::string& direction,
                          int msg_type);
    void remove_interface(const std::string& interface);
    std::unordered_map<std::string, DHCPCounters> get_counters_data();

    ~DHCPCounter_table();
};

uint64_t calculate_delta(uint64_t new_value, uint64_t old_value);
