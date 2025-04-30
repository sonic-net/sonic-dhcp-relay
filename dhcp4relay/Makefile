.ONESHELL:
SHELL = /bin/bash

RM := rm -rf
WORKING_DIR := $(abspath .)
BUILD_DIR := build
BUILD_TEST_DIR := build-test
DHCP4RELAY_TARGET := $(BUILD_DIR)/dhcp4relay
DHCP4RELAY_TEST_TARGET := $(BUILD_TEST_DIR)/dhcp4relay-test
CP := cp
MKDIR := mkdir
MV := mv
FIND := find
GCOVR := gcovr

LD_PCAPPLUSPLUS_LIB := -lPcap++ -lPacket++ -lCommon++

#pcap plus plus zip file pcappp_v24.09.zip
PCAPPPVAR := 24.09
PCAPPP_URL = https://github.com/seladb/PcapPlusPlus/releases/download/v${PCAPPPVAR}/pcapplusplus-${PCAPPPVAR}-ubuntu-20.04-gcc-9.4.0-x86_64.tar.gz
PCAPPLUSPLUS_DIR := $(WORKING_DIR)/pcapplusplus-$(PCAPPPVAR)-ubuntu-20.04-gcc-9.4.0-x86_64
PCAPPP_DONE = $(WORKING_DIR)/pcappp.stamp
INCLUDE_DIR = $(PCAPPLUSPLUS_DIR)/include
LIB_DIR = $(PCAPPLUSPLUS_DIR)/lib

override LDLIBS += -levent -lhiredis -lswsscommon -pthread -lboost_thread -lboost_system $(LD_PCAPPLUSPLUS_LIB) -lpcap
override CPPFLAGS += -Wall -std=c++17 -fPIE -I/usr/include/swss -I$(INCLUDE_DIR)
override CPPFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)"
override LDFLAGS += -L$(LIB_DIR) -Wl,-rpath=$(abspath $(LIB_DIR))
CPPFLAGS_TEST := --coverage -fprofile-arcs -ftest-coverage -fprofile-generate -fsanitize=address -DUNIT_TEST
LDLIBS_TEST := --coverage -lgtest -lgmock -pthread -lstdc++fs -fsanitize=address
PWD := $(shell pwd)

.PHONY: $(PCAPPP_DONE)
$(PCAPPP_DONE):
	wget $(PCAPPP_URL) -O pcapplusplus.tar.gz
	tar -xzf pcapplusplus.tar.gz
	touch $@ 
    
all: $(DHCP4RELAY_TARGET) $(DHCP4RELAY_TEST_TARGET)

-include src/subdir.mk
-include test/subdir.mk

# Use different build directories based on whether it's a regular build or a
# test build. This is because in the test build, code coverage is enabled,
# which means the object files that get built will be different
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)
TEST_OBJS = $(TEST_SRCS:%.cpp=$(BUILD_TEST_DIR)/%.o)

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=%.d)
-include $(TEST_OBJS:%.o=%.d)
endif

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

$(DHCP4RELAY_TARGET): $(PCAPPP_DONE) $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_TEST_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) -c -o $@ $<

$(DHCP4RELAY_TEST_TARGET): $(TEST_OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) $(LDLIBS_TEST) -o $@

test: $(DHCP4RELAY_TEST_TARGET)
	sudo ASAN_OPTIONS=detect_leaks=0 ./$(DHCP4RELAY_TEST_TARGET) --gtest_output=xml:$(DHCP4RELAY_TEST_TARGET)-test-result.xml || true
	$(GCOVR) -r ./ --html --html-details -o $(DHCP4RELAY_TEST_TARGET)-code-coverage.html
	$(GCOVR) -r ./ --xml-pretty -o $(DHCP4RELAY_TEST_TARGET)-code-coverage.xml

install: $(DHCP4RELAY_TARGET)
	install -D $(DHCP4RELAY_TARGET) $(DESTDIR)/usr/sbin/$(notdir $(DHCP4RELAY_TARGET))

uninstall:
	$(RM) $(DESTDIR)/usr/sbin/$(notdir $(DHCP4RELAY_TARGET))

clean:
	-$(RM) $(BUILD_DIR) $(BUILD_TEST_DIR) *.html *.xml pcap*
	$(FIND) . -name *.gcda -exec rm -f {} \;
	$(FIND) . -name *.gcno -exec rm -f {} \;
	$(FIND) . -name *.gcov -exec rm -f {} \;
	-@echo ' '

.PHONY: all clean test install uninstall
