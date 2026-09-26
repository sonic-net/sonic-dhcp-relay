#include "mock_config_interface.h"

#include <net/if.h>

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

  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, false, config_db));
  EXPECT_EQ(vlans.size(), 0);

  swssSelect.addSelectable(&ipHelpersTable);

  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, false, config_db));
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

TEST(configInterface, processRelayNotificationRejectsInvalidVlanName) {
  std::shared_ptr<swss::DBConnector> config_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  config_db->hset("VLAN_INTERFACE|Vlan1x|fc02:1000::1", "", "");
  std::deque<swss::KeyOpFieldsValuesTuple> entries = {
      {"Vlan1x", "SET", {{"dhcpv6_servers", "fc02:2000::1"}}}
  };
  std::unordered_map<std::string, relay_config> vlans;

  processRelayNotification(entries, vlans, config_db);

  EXPECT_TRUE(vlans.empty());
}

TEST(configInterface, validVlanInterfaceNames) {
  EXPECT_TRUE(is_valid_vlan_interface_name("Vlan1"));
  EXPECT_TRUE(is_valid_vlan_interface_name("Vlan1000"));
  EXPECT_TRUE(is_valid_vlan_interface_name("Vlan" + std::string(IFNAMSIZ - 5, '9')));
}

TEST(configInterface, invalidVlanInterfaceNames) {
  EXPECT_FALSE(is_valid_vlan_interface_name("Vlan"));
  EXPECT_FALSE(is_valid_vlan_interface_name("Ethernet0"));
  EXPECT_FALSE(is_valid_vlan_interface_name("Vlan-1"));
  EXPECT_FALSE(is_valid_vlan_interface_name("Vlan1x"));
  EXPECT_FALSE(is_valid_vlan_interface_name("Vlan1_2"));
  EXPECT_FALSE(is_valid_vlan_interface_name("Vlan" + std::string(IFNAMSIZ - 4, '9')));
}

MOCK_GLOBAL_FUNC0(stopSwssNotificationPoll, void(void));

TEST(configInterface, stopSwssNotificationPoll) {
  EXPECT_GLOBAL_CALL(stopSwssNotificationPoll, stopSwssNotificationPoll()).Times(1);
  ASSERT_NO_THROW(stopSwssNotificationPoll());
}

TEST(configInterface, check_is_lla_ready) {
  EXPECT_FALSE(check_is_lla_ready("Vlan1000"));
}
