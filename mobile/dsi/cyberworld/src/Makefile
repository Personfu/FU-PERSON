#───────────────────────────────────────────────────────────────────
#  CyberWorld — DSi Homebrew RPG | FLLC | devkitARM + libnds
#───────────────────────────────────────────────────────────────────

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment.")
endif

include $(DEVKITARM)/ds_rules

TARGET   := CyberWorld
BUILD    := build
SOURCES  := .
INCLUDES := .
LIBS     := -lfat -lnds9
LIBDIRS  := $(LIBNDS)

CFILES   := $(wildcard $(SOURCES)/*.c)
OFILES   := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(CFILES)))

CFLAGS   := -Wall -O2 -march=armv5te -mtune=arm946e-s -fomit-frame-pointer \
            -ffast-math $(INCLUDE)
LDFLAGS  := -specs=ds_arm9.specs -g $(ARCH)
INCLUDE  := $(foreach dir,$(INCLUDES),-I$(dir)) \
            $(foreach dir,$(LIBDIRS),-I$(dir)/include)
LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

.PHONY: all clean

all: $(TARGET).nds

$(TARGET).nds: $(TARGET).arm9
	ndstool -c $@ -9 $<

$(TARGET).arm9: $(OFILES)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBPATHS) $(LIBS)

$(BUILD)/%.o: $(SOURCES)/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(TARGET).arm9 $(TARGET).nds
