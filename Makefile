RM := rm -rf
DHCP6RELAY_TARGET := dhcp6relay
DHCP6RELAY_TEST_TARGET := dhcp6relay-test
CP := cp
MKDIR := mkdir
MV := mv
FIND := find
GCOVR := gcovr
GCOV_FLAGS := -fprofile-use -fprofile-arcs -ftest-coverage -fprofile-generate
override LDLIBS += -levent -lhiredis -lswsscommon -pthread -lboost_thread -lboost_system
override LDLIBS_TEST += -lgtest_main -lgtest -pthread -lstdc++fs
override CPPFLAGS += -Wall -std=c++17 -fPIE -I/usr/include/swss
override CPPFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)"
PWD := $(shell pwd)

test-targets: CPP_FLAGS = -O0 -Wall -fmessage-length=0 -fPIC $(GCOV_FLAGS)

all: $(DHCP6RELAY_TARGET) $(DHCP6RELAY_TEST_TARGET)

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=%.d)
endif

-include src/subdir.mk
-include test/subdir.mk

$(DHCP6RELAY_TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(DHCP6RELAY_TEST_TARGET): $(OBJS_DHCP6RELAY_TEST)
	$(CC) -lgcov --coverage -o "$(DHCP6RELAY_TEST_TARGET)" $(CPP_FLAGS) $(OBJS_DHCP6RELAY_TEST) $(LDLIBS) $(LDLIBS_TEST)
	./$(DHCP6RELAY_TEST_TARGET)
	$(GCOVR) -r ./ --html --html-details -o $(DHCP6RELAY_TEST_TARGET)-result.html
	$(GCOVR) -r ./ --xml-pretty -o $(DHCP6RELAY_TEST_TARGET)-result.xml


install:
	$(MKDIR) -p $(DESTDIR)/usr/sbin
	$(MV) $(DHCP6RELAY_TARGET) $(DESTDIR)/usr/sbin

deinstall:
	$(RM) $(DESTDIR)/usr/sbin/$(DHCP6RELAY_TARGET)
	$(RM) -rf $(DESTDIR)/usr/sbin

clean:
	-$(RM) $(EXECUTABLES) $(OBJS:%.o=%.d) $(OBJS) $(DHCP6RELAY_TARGET) $(DHCP6RELAY_TEST_TARGET) $(OBJS_DHCP6RELAY_TEST) *.html *.xml
	$(FIND) . -name *.gcda -exec rm -f {} \;
	$(FIND) . -name *.gcno -exec rm -f {} \;
	$(FIND) . -name *.gcov -exec rm -f {} \;
	-@echo ' '

.PHONY: all clean dependents


