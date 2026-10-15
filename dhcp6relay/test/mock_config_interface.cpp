#include <chrono>
#include <thread>
#include <unistd.h>
#include "mock_config_interface.h"

using namespace ::testing;

TEST(configInterface, initialize_swss) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_servers@", "fc02:2000::1,fc02:2000::2,fc02:2000::3,fc02:2000::4");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|rfc6939_support", "false");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|interface_id", "true");
  config_db->hset("VLAN_INTERFACE|Vlan1000|fc02:1000::1", "", "");
  std::unordered_map<std::string, relay_config> vlans;
  ASSERT_NO_THROW(initialize_swss(vlans));
  EXPECT_EQ(vlans.size(), 1);
}

TEST(configInterface, deinitialize_swss) {
  ASSERT_NO_THROW(deinitialize_swss());
}

TEST(configInterface, get_dhcp) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_servers@", "fc02:2000::1,fc02:2000::2,fc02:2000::3,fc02:2000::4");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|rfc6939_support", "false");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|interface_id", "true");
  swss::SubscriberStateTable ipHelpersTable(config_db.get(), "DHCP_RELAY");
  std::unordered_map<std::string, relay_config> vlans;

  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, config_db));
  EXPECT_EQ(vlans.size(), 0);

  swssSelect.addSelectable(&ipHelpersTable);

  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, config_db));
  EXPECT_EQ(vlans.size(), 1);
}

TEST(configInterface, handleRelayNotification) {
  std::shared_ptr<swss::DBConnector> cfg_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  swss::SubscriberStateTable ipHelpersTable(cfg_db.get(), "DHCP_RELAY");
  std::unordered_map<std::string, relay_config> vlans;
  handleRelayNotification(ipHelpersTable, vlans, cfg_db);
}

TEST(configInterface, processRelayNotification) {  
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_servers@", "fc02:2000::1,fc02:2000::2,fc02:2000::3,fc02:2000::4");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|rfc6939_support", "false");
  config_db->hset("DHCP_RELAY|Vlan1000", "dhcpv6_option|interface_id", "true");
  swss::SubscriberStateTable ipHelpersTable(config_db.get(), "DHCP_RELAY");
  swssSelect.addSelectable(&ipHelpersTable);
  std::deque<swss::KeyOpFieldsValuesTuple> entries;
  ipHelpersTable.pops(entries);
  std::unordered_map<std::string, relay_config> vlans;

  processRelayNotification(entries, vlans, config_db);

  EXPECT_EQ(vlans.size(), 1);
  EXPECT_FALSE(vlans["Vlan1000"].is_option_79);
  EXPECT_TRUE(vlans["Vlan1000"].is_interface_id);
  EXPECT_FALSE(vlans["Vlan1000"].state_db);
}

MOCK_GLOBAL_FUNC0(stopSwssNotificationPoll, void(void));

TEST(configInterface, stopSwssNotificationPoll) {
  EXPECT_GLOBAL_CALL(stopSwssNotificationPoll, stopSwssNotificationPoll()).Times(1);
  ASSERT_NO_THROW(stopSwssNotificationPoll());
}

TEST(configInterface, check_is_lla_ready) {
  EXPECT_FALSE(check_is_lla_ready("Vlan1000"));
}

TEST(configInterface, build_desired_config) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan2000", "dhcpv6_servers@", "fc02:2000::1,fc02:2000::2");
  config_db->hset("DHCP_RELAY|Vlan2000", "dhcpv6_option|rfc6939_support", "false");
  config_db->hset("DHCP_RELAY|Vlan2000", "dhcpv6_option|interface_id", "true");
  config_db->hset("VLAN_INTERFACE|Vlan2000|fc02:2000::1", "", "");

  auto desired = build_desired_config(config_db);
  ASSERT_EQ(desired.count("Vlan2000"), 1);
  EXPECT_EQ(desired["Vlan2000"].servers.size(), 2);
  EXPECT_FALSE(desired["Vlan2000"].is_option_79);
  EXPECT_TRUE(desired["Vlan2000"].is_interface_id);
}

TEST(configInterface, build_desired_config_skips_vlan_without_ipv6) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  // No VLAN_INTERFACE IPv6 address for Vlan3000, so it must not be relayed.
  config_db->hset("DHCP_RELAY|Vlan3000", "dhcpv6_servers@", "fc02:3000::1");

  auto desired = build_desired_config(config_db);
  EXPECT_EQ(desired.count("Vlan3000"), 0);
}

TEST(configInterface, build_desired_config_interface_id_default_tracks_dualtor) {
  // The interface-id option defaults to enabled in Dual-ToR mode and disabled
  // otherwise. build_desired_config (used by the runtime config monitor) must
  // honour this default for a VLAN whose DHCP_RELAY entry does not set
  // dhcpv6_option|interface_id explicitly, in both Dual-ToR and non-Dual-ToR
  // mode. dual_tor_sock is fixed at startup from the -u option.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan4200", "dhcpv6_servers@", "fc02:4200::1");
  config_db->hset("VLAN_INTERFACE|Vlan4200|fc02:4200::1", "", "");

  bool saved_dual_tor_sock = dual_tor_sock;

  // Non-Dual-ToR: interface-id default is disabled.
  dual_tor_sock = false;
  auto desired_non_dualtor = build_desired_config(config_db);
  ASSERT_EQ(desired_non_dualtor.count("Vlan4200"), 1);
  EXPECT_FALSE(desired_non_dualtor["Vlan4200"].is_interface_id);

  // Dual-ToR: interface-id default is enabled.
  dual_tor_sock = true;
  auto desired_dualtor = build_desired_config(config_db);
  ASSERT_EQ(desired_dualtor.count("Vlan4200"), 1);
  EXPECT_TRUE(desired_dualtor["Vlan4200"].is_interface_id);

  // Restore the global so the mode does not leak into other tests.
  dual_tor_sock = saved_dual_tor_sock;

  config_db->del("DHCP_RELAY|Vlan4200");
  config_db->del("VLAN_INTERFACE|Vlan4200|fc02:4200::1");
}

TEST(configInterface, fetch_desired_config) {
  std::unordered_map<std::string, relay_config> out;
  EXPECT_TRUE(fetch_desired_config(out));
}

TEST(configInterface, start_stop_dhcp_config_monitor) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan4000", "dhcpv6_servers@", "fc02:4000::1");
  config_db->hset("VLAN_INTERFACE|Vlan4000|fc02:4000::1", "", "");

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);

  // Start the monitor thread; it reads CONFIG_DB, publishes the desired config
  // and wakes the (read end of the) notify pipe.
  ASSERT_NO_THROW(start_dhcp_config_monitor(pipefd[1]));
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  std::unordered_map<std::string, relay_config> out;
  EXPECT_TRUE(fetch_desired_config(out));

  // Stop the monitor and give the select loop time to observe the stop flag.
  ASSERT_NO_THROW(stop_dhcp_config_monitor());
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  close(pipefd[0]);
  close(pipefd[1]);
}

TEST(configInterface, config_monitor_reacts_to_dhcp_relay) {
  // A DHCPv6 relay server list added at runtime on a VLAN that already has an
  // IPv6 interface must wake the monitor and appear in the republished config.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("VLAN_INTERFACE|Vlan4101|fc02:4101::1", "", "");

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);
  evutil_make_socket_nonblocking(pipefd[0]);

  ASSERT_NO_THROW(start_dhcp_config_monitor(pipefd[1]));
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  char drain[64];
  while (read(pipefd[0], drain, sizeof(drain)) > 0) { /* discard startup wake */ }

  // Runtime change the monitor watches on CONFIG_DB DHCP_RELAY.
  config_db->hset("DHCP_RELAY|Vlan4101", "dhcpv6_servers@", "fc02:4101::100");

  ssize_t got = -1;
  for (int i = 0; i < 30 && got <= 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    got = read(pipefd[0], drain, sizeof(drain));
  }
  EXPECT_GT(got, 0);

  std::unordered_map<std::string, relay_config> out;
  EXPECT_TRUE(fetch_desired_config(out));
  EXPECT_EQ(out.count("Vlan4101"), 1);

  ASSERT_NO_THROW(stop_dhcp_config_monitor());
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  config_db->del("DHCP_RELAY|Vlan4101");
  config_db->del("VLAN_INTERFACE|Vlan4101|fc02:4101::1");
  close(pipefd[0]);
  close(pipefd[1]);
}

TEST(configInterface, config_change_callback_applies_update) {
  // Seed the desired config via the monitor, then confirm the libevent callback
  // drains its notify pipe and applies the update to an active live relay.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("VLAN_INTERFACE|Vlan4102|fc02:4102::1", "", "");
  config_db->hset("DHCP_RELAY|Vlan4102", "dhcpv6_servers@", "fc02:4102::100,fc02:4102::200");

  int wake[2];
  ASSERT_EQ(pipe(wake), 0);
  ASSERT_NO_THROW(start_dhcp_config_monitor(wake[1]));
  std::unordered_map<std::string, relay_config> desired;
  for (int i = 0; i < 30; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    desired.clear();
    fetch_desired_config(desired);
    if (desired.count("Vlan4102")) break;
  }
  ASSERT_NO_THROW(stop_dhcp_config_monitor());
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  ASSERT_EQ(desired.count("Vlan4102"), 1);

  // Live relay has one server; the callback must apply the two-server desired.
  std::unordered_map<std::string, relay_config> vlans;
  relay_config live{};
  live.interface = "Vlan4102";
  live.servers = {"fc02:4102::100"};
  live.is_lla_ready = true;
  vlans["Vlan4102"] = live;

  int notify[2];
  ASSERT_EQ(pipe(notify), 0);
  evutil_make_socket_nonblocking(notify[0]);
  ASSERT_EQ(write(notify[1], "x", 1), 1);

  config_apply_ctx ctx{&vlans, nullptr, nullptr, notify[0]};
  ASSERT_NO_THROW(config_change_callback(notify[0], 0, &ctx));

  EXPECT_EQ(vlans["Vlan4102"].servers.size(), 2);
  EXPECT_EQ(vlans["Vlan4102"].servers_sock.size(), 2);

  config_db->del("DHCP_RELAY|Vlan4102");
  config_db->del("VLAN_INTERFACE|Vlan4102|fc02:4102::1");
  close(wake[0]);
  close(wake[1]);
  close(notify[0]);
  close(notify[1]);
}

TEST(configInterface, start_monitor_twice_restarts) {
  // Starting the monitor while one is already running must stop the previous
  // thread first (the double-start guard) instead of leaking it.
  int a[2], b[2];
  ASSERT_EQ(pipe(a), 0);
  ASSERT_EQ(pipe(b), 0);

  ASSERT_NO_THROW(start_dhcp_config_monitor(a[1]));
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ASSERT_NO_THROW(start_dhcp_config_monitor(b[1]));
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  ASSERT_NO_THROW(stop_dhcp_config_monitor());
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  close(a[0]);
  close(a[1]);
  close(b[0]);
  close(b[1]);
}
