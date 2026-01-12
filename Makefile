export BUILD_SYSTEM_DIR := vendor/nimbus-build-system
export EXCLUDED_NIM_PACKAGES := vendor/nwaku/vendor/nim-dnsdisc/vendor \
								vendor/nwaku/vendor/nimbus-build-system \
								vendor/nim-sds/vendor
LINK_PCRE := 0
FORMAT_MSG := "\\x1B[95mFormatting:\\x1B[39m"
# we don't want an error here, so we can handle things later, in the ".DEFAULT" target
-include $(BUILD_SYSTEM_DIR)/makefiles/variables.mk

ifeq ($(NIM_PARAMS),)
# "variables.mk" was not included, so we update the submodules.
GIT_SUBMODULE_UPDATE := git submodule update --init --recursive
.DEFAULT:
	+@ echo -e "Git submodules not found. Running '$(GIT_SUBMODULE_UPDATE)'.\n"; \
		$(GIT_SUBMODULE_UPDATE); \
		echo
# Now that the included *.mk files appeared, and are newer than this file, Make will restart itself:
# https://www.gnu.org/software/make/manual/make.html#Remaking-Makefiles
#
# After restarting, it will execute its original goal, so we don't have to start a child Make here
# with "$(MAKE) $(MAKECMDGOALS)". Isn't hidden control flow great?

else # "variables.mk" was included. Business as usual until the end of this file.

# Determine the OS
detected_OS := $(shell uname -s)
ifneq (,$(findstring MINGW,$(detected_OS)))
  detected_OS := Windows
endif

##########
## Main ##
##########
.PHONY: all update clean

# default target, because it's the first one that doesn't start with '.'
all: | bot_echo pingpong

test_file := $(word 2,$(MAKECMDGOALS))
define test_name
$(shell echo '$(MAKECMDGOALS)' | cut -d' ' -f3-)
endef

nim_chat_poc.nims:
	ln -s nim_chat_poc.nimble $@

update: | update-common
	rm -rf nim_chat_poc.nims && \
		$(MAKE) nim_chat_poc.nims $(HANDLE_OUTPUT)

clean:
	rm -rf build

# must be included after the default target
-include $(BUILD_SYSTEM_DIR)/makefiles/targets.mk

## Possible values: prod; debug
TARGET ?= prod

## Git version
GIT_VERSION ?= $(shell git describe --abbrev=6 --always --tags)
## Compilation parameters. If defined in the CLI the assignments won't be executed
NIM_PARAMS := $(NIM_PARAMS) -d:git_version=\"$(GIT_VERSION)\"

##################
## Dependencies ##
##################
.PHONY: build-waku-librln

LIBRLN_VERSION := v0.7.0

ifeq ($(detected_OS),Windows)
LIBRLN_FILE := rln.lib
else
LIBRLN_FILE := librln_$(LIBRLN_VERSION).a
endif


build-waku-librln:
	@echo "Start building waku librln"
	$(MAKE) -C vendor/nwaku librln
	$(eval NIM_PARAMS += --passL:./vendor/nwaku/${LIBRLN_FILE} --passL:-lm)
	@echo "Completed building librln"

build-waku-nat:
	@echo "Start building waku nat-libs"
	$(MAKE) -C vendor/nwaku nat-libs
	@echo "Completed building nat-libs"
	
.PHONY: tests
tests: | build-waku-librln build-waku-nat nim_chat_poc.nims
	echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) nim tests $(NIM_PARAMS) nim_chat_poc.nims


##########
## Example ##
##########

# Ensure there is a nimble task with a name that matches the target
tui bot_echo pingpong: | build-waku-librln build-waku-nat nim_chat_poc.nims
	echo -e $(BUILD_MSG) "build/$@" && \
	$(ENV_SCRIPT) nim $@ $(NIM_PARAMS) --path:src nim_chat_poc.nims

###########
## Library ##
###########

# Determine shared library extension based on OS
ifeq ($(shell uname -s),Darwin)
  LIBCHAT_EXT := dylib
else ifeq ($(shell uname -s),Linux)
  LIBCHAT_EXT := so
else
  LIBCHAT_EXT := dll
endif

LIBCHAT := build/libchat.$(LIBCHAT_EXT)

.PHONY: libchat
libchat: | build-waku-librln build-waku-nat nim_chat_poc.nims
	echo -e $(BUILD_MSG) "$(LIBCHAT)" && \
	$(ENV_SCRIPT) nim libchat $(NIM_PARAMS) --path:src nim_chat_poc.nims && \
	echo -e "\n\x1B[92mLibrary built successfully:\x1B[39m" && \
	echo "  $(shell pwd)/$(LIBCHAT)"

endif


