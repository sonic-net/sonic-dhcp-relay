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

   public:
    DHCPMgr() : stop_thread(false) {}
    ~DHCPMgr();

    void initialize_config_listner();
    void handle_swss_notification();
    void process_relay_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_interface_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
    void process_device_metadata_notification(std::deque<swss::KeyOpFieldsValuesTuple> &entries);
};
