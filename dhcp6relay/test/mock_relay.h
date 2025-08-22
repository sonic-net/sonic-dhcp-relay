#pragma once

#include "../src/relay.h"
#include "mock_send.h" 
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "../../gmock_global/include/gmock-global/gmock-global.h"
#include <new>
#include <future>

extern struct event_base *base;
extern struct event *ev_sigint;
extern struct event *ev_sigterm;
extern std::unordered_map<std::string, std::string> vlan_map;
extern std::unordered_map<std::string, std::string> addr_vlan_map;
