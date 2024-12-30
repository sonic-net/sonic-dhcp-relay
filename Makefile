.ONESHELL:
SHELL = /bin/bash

RM := rm -rf
BUILD_DIR := build
BUILD_TEST_DIR := build-test
DHCP6RELAY_TARGET := $(BUILD_DIR)/dhcp6relay
DHCP6RELAY_TEST_TARGET := $(BUILD_TEST_DIR)/dhcp6relay-test
CP := cp
MKDIR := mkdir
MV := mv
FIND := find
GCOVR := gcovr
override LDLIBS += -levent -lhiredis -lswsscommon -pthread -lboost_thread -lboost_system
override CPPFLAGS += -Wall -std=c++17 -fPIE -I/usr/include/swss
override CPPFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)"
CPPFLAGS_TEST := --coverage -fprofile-arcs -ftest-coverage -fprofile-generate -fsanitize=address
LDLIBS_TEST := --coverage -lgtest -lgmock -pthread -lstdc++fs -fsanitize=address
PWD := $(shell pwd)

all: $(DHCP6RELAY_TARGET) $(DHCP6RELAY_TEST_TARGET)

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

$(DHCP6RELAY_TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_TEST_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) -c -o $@ $<

$(DHCP6RELAY_TEST_TARGET): $(TEST_OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) $(LDLIBS_TEST) -o $@

test: $(DHCP6RELAY_TEST_TARGET)
	sudo ASAN_OPTIONS=detect_leaks=0 ./$(DHCP6RELAY_TEST_TARGET) --gtest_output=xml:$(DHCP6RELAY_TEST_TARGET)-test-result.xml || true
	$(GCOVR) -r ./ --html --html-details -o $(DHCP6RELAY_TEST_TARGET)-code-coverage.html
	$(GCOVR) -r ./ --xml-pretty -o $(DHCP6RELAY_TEST_TARGET)-code-coverage.xml

install: $(DHCP6RELAY_TARGET)
	install -D $(DHCP6RELAY_TARGET) $(DESTDIR)/usr/sbin/$(notdir $(DHCP6RELAY_TARGET))

uninstall:
	$(RM) $(DESTDIR)/usr/sbin/$(notdir $(DHCP6RELAY_TARGET))

clean:
	-$(RM) $(BUILD_DIR) $(BUILD_TEST_DIR) *.html *.xml
	$(FIND) . -name *.gcda -exec rm -f {} \;
	$(FIND) . -name *.gcno -exec rm -f {} \;
	$(FIND) . -name *.gcov -exec rm -f {} \;
	-@echo ' '

.PHONY: all clean test install uninstall
