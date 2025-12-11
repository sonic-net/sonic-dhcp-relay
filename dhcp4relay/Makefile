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

# PcapPlusPlus library configuration
PCAPPPVAR := 24.09
PCAPPP_URL := https://github.com/seladb/PcapPlusPlus/archive/refs/tags/v$(PCAPPPVAR).tar.gz
PCAPPP_TARBALL := PcapPlusPlus-$(PCAPPPVAR).tar.gz
PCAPPP_SHA256 := b14998ecf5718c2bfb6f709060e53f7ef67639b98bf2222a3cd23d820d70acdc
PCAPPLUSPLUS_DIR := $(WORKING_DIR)/PcapPlusPlus-$(PCAPPPVAR)
PCAPPP_DONE = $(WORKING_DIR)/pcappp.stamp
INCLUDE_DIR = $(PCAPPLUSPLUS_DIR)/include
LIB_DIR = $(PCAPPLUSPLUS_DIR)/lib

override LDLIBS += -levent -lhiredis -lswsscommon -pthread -lboost_thread $(LD_PCAPPLUSPLUS_LIB) -lpcap
override CPPFLAGS += -Wall -std=c++17 -fPIE -I/usr/include/swss -I$(INCLUDE_DIR)
override CPPFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)"
override LDFLAGS += -L$(LIB_DIR) -Wl,-rpath=$(abspath $(LIB_DIR))
CPPFLAGS_TEST := --coverage -fprofile-arcs -ftest-coverage -fprofile-generate -fsanitize=address -DUNIT_TEST
LDLIBS_TEST := --coverage -lgtest -lgmock -pthread -lstdc++fs -fsanitize=address
PWD := $(shell pwd)

.PHONY: $(PCAPPP_DONE)
$(PCAPPP_DONE):

	# Download PcapPlusPlus from official GitHub release if not already present
	if [ ! -f $(PCAPPP_TARBALL) ]; then \
		echo "Downloading PcapPlusPlus v$(PCAPPPVAR)..."; \
		wget -O $(PCAPPP_TARBALL) $(PCAPPP_URL); \
	fi

	# Verify checksum
	echo "$(PCAPPP_SHA256)  $(PCAPPP_TARBALL)" | sha256sum -c -

	# Remove stale files
	rm -rf $(PCAPPLUSPLUS_DIR)

	# Extract tarball (GitHub tarball extracts to PcapPlusPlus-<version> without 'v' prefix)
	tar xzf $(PCAPPP_TARBALL)
	pushd $(PCAPPLUSPLUS_DIR)

	# Create a git repository here for stg to apply patches
	git init
	git add -f *
	git commit -qm "initial commit"

	# Apply patches
	stg init
	stg import -s ../patch/series
	popd

	cd $(PCAPPLUSPLUS_DIR) && cmake -S . -B build && cmake --build build
	cd build && make && sudo cmake --install .

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
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) $(LDLIBS) -c -o $@ $<

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
	-$(RM) $(BUILD_DIR) $(BUILD_TEST_DIR) *.html *.xml
	-$(RM) $(PCAPPLUSPLUS_DIR) $(PCAPPP_TARBALL) $(PCAPPP_DONE)
	$(FIND) . -name *.gcda -exec rm -f {} \;
	$(FIND) . -name *.gcno -exec rm -f {} \;
	$(FIND) . -name *.gcov -exec rm -f {} \;
	-@echo ' '

.PHONY: all clean test install uninstall
