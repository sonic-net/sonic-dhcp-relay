#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/UdpLayer.h>
#include "gtest/gtest.h"

TEST(PcapSonicsPatch, RecognizesEphemeralDhcpPorts) {
    EXPECT_TRUE(pcpp::DhcpLayer::isDhcpPorts(49152, 67));
    EXPECT_TRUE(pcpp::DhcpLayer::isDhcpPorts(49153, 68));
    EXPECT_FALSE(pcpp::DhcpLayer::isDhcpPorts(67, 69));
    EXPECT_TRUE(pcpp::DhcpLayer::isDhcpPorts(68, 67));
}
TEST(PcapSonicsPatch, ParsesPacketThroughPatchedClassifier) {
    pcpp::EthLayer ethernet(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("ff:ff:ff:ff:ff:ff"));
    pcpp::IPv4Layer ip(pcpp::IPv4Address("0.0.0.0"), pcpp::IPv4Address("255.255.255.255"));
    pcpp::UdpLayer udp(49152, 67);
    pcpp::DhcpLayer dhcp(pcpp::DHCP_DISCOVER, pcpp::MacAddress("00:11:22:33:44:55"));
    pcpp::Packet packet(600);
    ASSERT_TRUE(packet.addLayer(&ethernet));
    ASSERT_TRUE(packet.addLayer(&ip));
    ASSERT_TRUE(packet.addLayer(&udp));
    ASSERT_TRUE(packet.addLayer(&dhcp));
    packet.computeCalculateFields();
    pcpp::Packet parsed(packet.getRawPacket());
    ASSERT_NE(parsed.getLayerOfType<pcpp::DhcpLayer>(), nullptr);
    EXPECT_EQ(parsed.getLayerOfType<pcpp::DhcpLayer>()->getMessageType(), pcpp::DHCP_DISCOVER);
}
