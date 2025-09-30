#pragma once

#include "../src/dhcp4relay.h"
#include "../src/dhcp4relay_mgr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "../../gmock_global/include/gmock-global/gmock-global.h"
#include <new>
#include <future>

extern struct event_base *base;
extern struct event *ev_sigint;
extern struct event *ev_sigterm;
extern std::unordered_map<std::string, std::string> vlan_map;
extern std::unordered_map<std::string, std::string> vlan_vrf_map;
extern swss::Select swssSelect;
extern std::unordered_map<std::string, VrfSocketInfo> vrf_sock_map;
extern std::unordered_map<std::string, std::string> phy_interface_alias_map;
extern std::vector<std::string> interface_list;
