RM := rm -rf
DHCP6RELAY_TARGET := dhcp6relay
CP := cp
MKDIR := mkdir
MV := mv
override LDLIBS += -levent -lhiredis -lswsscommon -pthread -lboost_thread -lboost_system
override CPPFLAGS += -Wall -std=c++17 -fPIE -I/usr/include/swss
override CPPFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)"
PWD := $(shell pwd)

all: $(DHCP6RELAY_TARGET)

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=%.d)
endif

-include src/subdir.mk

$(DHCP6RELAY_TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

install:
	$(MKDIR) -p $(DESTDIR)/usr/sbin
	$(MV) $(DHCP6RELAY_TARGET) $(DESTDIR)/usr/sbin

deinstall:
	$(RM) $(DESTDIR)/usr/sbin/$(DHCP6RELAY_TARGET)
	$(RM) -rf $(DESTDIR)/usr/sbin

clean:
	-$(RM) $(EXECUTABLES) $(OBJS:%.o=%.d) $(OBJS) $(DHCP6RELAY_TARGET)
	-@echo ' '

.PHONY: all clean dependents
