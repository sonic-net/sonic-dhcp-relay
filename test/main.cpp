#include "gtest/gtest.h"
#include <swss/dbconnector.h>
#include <string>

std::string database_config = "./test/database_config.json";

class DhcpRelayEnvironment : public ::testing::Environment {
public:
    // Override this to define how to set up the environment.
    void SetUp() override {
        // by default , init should be false
        EXPECT_FALSE(swss::SonicDBConfig::isInit());

        // load local config file, init should be true
        swss::SonicDBConfig::initialize(database_config);
        EXPECT_TRUE(swss::SonicDBConfig::isInit());
    }
};

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);
    // Registers a global test environment, and verifies that the
    // registration function returns its argument.
    DhcpRelayEnvironment* env = new DhcpRelayEnvironment;
    testing::AddGlobalTestEnvironment(env);
    return RUN_ALL_TESTS();
}
