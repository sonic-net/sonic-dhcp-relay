#pragma once

#include "../src/config_interface.h"
#include "mock_send.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#ifdef BAZEL_TEST_BUILD
#include "gmock-global/gmock-global.h"
#else
#include "../../gmock_global/include/gmock-global/gmock-global.h"
#endif
#include <new>
#include <future>

extern bool pollSwssNotifcation;
extern swss::Select swssSelect;
