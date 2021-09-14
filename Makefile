XBE_TITLE = nxdk_launch_test
GEN_XISO = $(XBE_TITLE).iso
NXDK_DIR ?= $(CURDIR)/../nxdk
NXDK_CXX = y

DEBUG = y

SRCS = $(wildcard $(CURDIR)/primary_process/*.cpp)

CXXFLAGS += -Wall -Wextra -std=gnu++11
CFLAGS   += -std=gnu11

ifeq ($(DEBUG),y)
CFLAGS += -I$(CURDIR) -DDEBUG -D_DEBUG
CXXFLAGS += -I$(CURDIR) -DDEBUG -D_DEBUG
endif


include $(NXDK_DIR)/Makefile

RESOURCES += $(OUTPUT_DIR)/sub_process.xbe
TARGET += $(RESOURCES)
$(GEN_XISO): $(RESOURCES)

$(OUTPUT_DIR)/sub_process.xbe: sub_process/bin/default.xbe
	$(VE)mkdir -p '$(dir $@)'
	$(VE)cp '$<' '$@'

.PHONY: sub_process/bin/default.xbe
sub_process/bin/default.xbe:
	@echo "[ BUILD    ] $@"
	$(VE)$(MAKE) -C $(CURDIR)/sub_process $(QUIET)
