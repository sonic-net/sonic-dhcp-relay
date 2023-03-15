#include "mock_config_interface.h"

using namespace ::testing;

class MockSwssSelect : public swss::Select {
public:
  MOCK_METHOD(void, addSelectable, (swss::Selectable *));
  MOCK_METHOD(int, select, (swss::Selectable **c, int timeout,
              bool interrupt_on_signal));
};

TEST(configInterface, initialize_swss) {
  std::unordered_map<std::string, relay_config> vlans;
  MockSwssSelect obj_mock;
  EXPECT_CALL(obj_mock, addSelectable(NULL)).Times(1);
  ASSERT_NO_THROW(initialize_swss(vlans));
  std::bad_alloc exception;
  EXPECT_CALL(obj_mock, addSelectable(NULL)).Times(1).WillOnce(Throw(exception));
  ASSERT_ANY_THROW(initialize_swss(vlans));
}

class MockThread : public boost::thread {
public:
  MOCK_METHOD(void, interrupt, ());
};

TEST(configInterface, deinitialize_swss) {
  ASSERT_NO_THROW(deinitialize_swss());
}

TEST(configInterface, get_dhcp) {
  std::shared_ptr<swss::DBConnector> cfg_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  swss::SubscriberStateTable ipHelpersTable(cfg_db.get(), "DHCP_RELAY");
  std::unordered_map<std::string, relay_config> vlans;
  MockSwssSelect obj_mock;
  EXPECT_CALL(obj_mock, select(_, 1000, false)).Times(1).WillOnce(Return(swss::Select::ERROR));
  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, false));
  EXPECT_CALL(obj_mock, select(_, 1000, false)).Times(1).WillOnce(DoAll(SetArgPointee<0>(&ipHelpersTable), Return(swss::Select::TIMEOUT)));
  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, false));
  EXPECT_CALL(obj_mock, select(_, 1000, false)).Times(1).WillOnce(DoAll(SetArgPointee<0>(&ipHelpersTable), Return(swss::Select::TIMEOUT)));
  ASSERT_NO_THROW(get_dhcp(vlans, &ipHelpersTable, true));
}

TEST(configInterface, handleRelayNotification) {
  std::shared_ptr<swss::DBConnector> cfg_db = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
  swss::SubscriberStateTable ipHelpersTable(cfg_db.get(), "DHCP_RELAY");
  std::unordered_map<std::string, relay_config> vlans;
  handleRelayNotification(ipHelpersTable, vlans);
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

  processRelayNotification(entries, vlans);

  EXPECT_EQ(vlans.size(), 1);
  EXPECT_FALSE(vlans["Vlan1000"].is_option_79);
  EXPECT_TRUE(vlans["Vlan1000"].is_interface_id);
  EXPECT_FALSE(vlans["Vlan1000"].state_db);
}

TEST(configInterface, handleSwssNotification) {
  Assign(&pollSwssNotifcation, false);
  swssNotification swss_notification;
  swss_notification.ipHelpersTable = nullptr;
  handleSwssNotification(swss_notification);
  EXPECT_EQ(swss_notification.vlans.size(), 0);
  EXPECT_EQ(swss_notification.ipHelpersTable, nullptr);

  Assign(&pollSwssNotifcation, true);
  std::async(std::launch::async, [&] () {handleSwssNotification(swss_notification);}).wait_for(std::chrono::milliseconds{200});
}

TEST(configInterface, stopSwssNotificationPoll) {
  EXPECT_GLOBAL_CALL(stopSwssNotificationPoll, stopSwssNotificationPoll()).Times(1);
  stopSwssNotificationPoll();
}