#pragma once

#include "../src/config_interface.h"
#include "mock_send.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gmock-global.h"
#include <new>
#include <future>

extern std::shared_ptr<boost::thread> mSwssThreadPtr;
extern bool pollSwssNotifcation;
extern swss::Select swssSelect;

MOCK_GLOBAL_FUNC3(get_dhcp, void(std::unordered_map<std::string, relay_config> &vlans,
                  swss::SubscriberStateTable *ipHelpersTable, bool dynamic));

