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

TEST(configInterface, build_desired_config_vrf_from_vlan_interface) {
  // A VLAN bound to a non-default VRF (VLAN_INTERFACE vrf_name) with no explicit
  // server_vrf: the upstream socket VRF tracks the VLAN's own vrf_name and there
  // is no separate server VRF.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan5000", "dhcpv6_servers@", "fc02:5000::1");
  config_db->hset("VLAN_INTERFACE|Vlan5000", "vrf_name", "Vrf-RED");
  config_db->hset("VLAN_INTERFACE|Vlan5000|fc02:5000::1", "", "");

  auto desired = build_desired_config(config_db);
  ASSERT_EQ(desired.count("Vlan5000"), 1);
  EXPECT_EQ(desired["Vlan5000"].vrf, "Vrf-RED");
  EXPECT_EQ(desired["Vlan5000"].server_vrf, "");

  config_db->del("DHCP_RELAY|Vlan5000");
  config_db->del("VLAN_INTERFACE|Vlan5000");
  config_db->del("VLAN_INTERFACE|Vlan5000|fc02:5000::1");
}

TEST(configInterface, build_desired_config_server_vrf_distinct_from_vlan_vrf) {
  // An explicit server_vrf different from the VLAN's vrf_name is preserved
  // separately: the gua socket binds the VLAN VRF and the servers are reached via
  // the distinct server VRF.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan5100", "dhcpv6_servers@", "fc02:5100::1");
  config_db->hset("DHCP_RELAY|Vlan5100", "server_vrf", "Vrf-BLUE");
  config_db->hset("VLAN_INTERFACE|Vlan5100", "vrf_name", "Vrf-RED");
  config_db->hset("VLAN_INTERFACE|Vlan5100|fc02:5100::1", "", "");

  auto desired = build_desired_config(config_db);
  ASSERT_EQ(desired.count("Vlan5100"), 1);
  EXPECT_EQ(desired["Vlan5100"].vrf, "Vrf-RED");
  EXPECT_EQ(desired["Vlan5100"].server_vrf, "Vrf-BLUE");

  config_db->del("DHCP_RELAY|Vlan5100");
  config_db->del("VLAN_INTERFACE|Vlan5100");
  config_db->del("VLAN_INTERFACE|Vlan5100|fc02:5100::1");
}

TEST(configInterface, build_desired_config_server_vrf_same_as_vlan_vrf_is_cleared) {
  // When server_vrf equals the VLAN's own vrf_name the servers are already
  // reachable on the gua socket, so server_vrf is cleared (no separate socket).
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan5150", "dhcpv6_servers@", "fc02:5150::1");
  config_db->hset("DHCP_RELAY|Vlan5150", "server_vrf", "Vrf-RED");
  config_db->hset("VLAN_INTERFACE|Vlan5150", "vrf_name", "Vrf-RED");
  config_db->hset("VLAN_INTERFACE|Vlan5150|fc02:5150::1", "", "");

  auto desired = build_desired_config(config_db);
  ASSERT_EQ(desired.count("Vlan5150"), 1);
  EXPECT_EQ(desired["Vlan5150"].vrf, "Vrf-RED");
  EXPECT_EQ(desired["Vlan5150"].server_vrf, "");

  config_db->del("DHCP_RELAY|Vlan5150");
  config_db->del("VLAN_INTERFACE|Vlan5150");
  config_db->del("VLAN_INTERFACE|Vlan5150|fc02:5150::1");
}

TEST(configInterface, build_desired_config_vrf_defaults_to_global) {
  // No vrf_name and no server_vrf: the vrf resolves to the global (default) table
  // and there is no separate server VRF.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan5200", "dhcpv6_servers@", "fc02:5200::1");
  config_db->hset("VLAN_INTERFACE|Vlan5200|fc02:5200::1", "", "");

  auto desired = build_desired_config(config_db);
  ASSERT_EQ(desired.count("Vlan5200"), 1);
  EXPECT_EQ(desired["Vlan5200"].vrf, "default");
  EXPECT_EQ(desired["Vlan5200"].server_vrf, "");

  config_db->del("DHCP_RELAY|Vlan5200");
  config_db->del("VLAN_INTERFACE|Vlan5200|fc02:5200::1");
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

TEST(configInterface, config_monitor_reacts_to_state_db_interface_table) {
  // The monitor also watches STATE_DB INTERFACE_TABLE so that a vlan whose
  // interface becomes ready after startup is reconciled immediately. Drive a
  // STATE_DB INTERFACE_TABLE change while the monitor runs and confirm the
  // monitor wakes (the notify pipe receives a byte) and re-publishes the
  // desired config.
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("DHCP_RELAY|Vlan4100", "dhcpv6_servers@", "fc02:4100::1");
  config_db->hset("VLAN_INTERFACE|Vlan4100|fc02:4100::1", "", "");

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);
  evutil_make_socket_nonblocking(pipefd[0]);

  ASSERT_NO_THROW(start_dhcp_config_monitor(pipefd[1]));
  // Let the monitor publish its startup snapshot and drain that wake byte.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  char drain[64];
  while (read(pipefd[0], drain, sizeof(drain)) > 0) { /* discard startup wake */ }

  // A STATE_DB INTERFACE_TABLE change must wake the monitor's select loop.
  std::shared_ptr<swss::DBConnector> state_db = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
  state_db->hset("INTERFACE_TABLE|Vlan4100|fc02:4100::1", "state", "ok");

  // The monitor should re-publish after the STATE_DB change (notify byte). Poll
  // for up to ~3s to stay robust to scheduling/keyspace-notification latency.
  ssize_t got = -1;
  for (int i = 0; i < 30 && got <= 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    got = read(pipefd[0], drain, sizeof(drain));
  }
  EXPECT_GT(got, 0);

  // And the latest published desired config still contains the relayed vlan.
  std::unordered_map<std::string, relay_config> out;
  EXPECT_TRUE(fetch_desired_config(out));
  EXPECT_EQ(out.count("Vlan4100"), 1);

  ASSERT_NO_THROW(stop_dhcp_config_monitor());
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  // Clean up the keys this test added so it does not perturb the shared redis
  // state other tests rely on.
  config_db->del("DHCP_RELAY|Vlan4100");
  config_db->del("VLAN_INTERFACE|Vlan4100|fc02:4100::1");
  state_db->del("INTERFACE_TABLE|Vlan4100|fc02:4100::1");

  close(pipefd[0]);
  close(pipefd[1]);
}
