#pragma once

#include "../src/config_interface.h"
#include "mock_send.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "../../gmock_global/include/gmock-global/gmock-global.h"
#include <new>
#include <future>

extern bool pollSwssNotifcation;
extern swss::Select swssSelect;
