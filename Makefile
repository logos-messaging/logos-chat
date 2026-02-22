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
all: | bot_echo pingpong liblogoschat

test_file := $(word 2,$(MAKECMDGOALS))
define test_name
$(shell echo '$(MAKECMDGOALS)' | cut -d' ' -f3-)
endef

logos_chat.nims:
	ln -s logos_chat.nimble $@

update: | update-common
	rm -rf logos_chat.nims && \
		$(MAKE) logos_chat.nims $(HANDLE_OUTPUT)

clean:
	rm -rf build
	cd vendor/libchat && cargo clean

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

.PHONY: build-libchat
build-libchat:
	@echo "Start building libchat"
	cd vendor/libchat && cargo build --release
	@echo "Completed building libchat"

.PHONY: tests
tests: | build-waku-librln build-waku-nat build-libchat logos_chat.nims
	echo -e $(BUILD_MSG) "build/$@" && \
		$(ENV_SCRIPT) nim tests $(NIM_PARAMS) logos_chat.nims


##########
## Example ##
##########

# Ensure there is a nimble task with a name that matches the target
tui bot_echo pingpong: | build-waku-librln build-waku-nat build-libchat logos_chat.nims
	echo -e $(BUILD_MSG) "build/$@" && \
	$(ENV_SCRIPT) nim $@ $(NIM_PARAMS) --path:src logos_chat.nims

###########
## Library ##
###########

# Determine shared library extension based on OS
ifeq ($(shell uname -s),Darwin)
  LIBLOGOSCHAT_EXT := dylib
else ifeq ($(shell uname -s),Linux)
  LIBLOGOSCHAT_EXT := so
else
  LIBLOGOSCHAT_EXT := dll
endif

LIBLOGOSCHAT := build/liblogoschat.$(LIBLOGOSCHAT_EXT)

.PHONY: liblogoschat
liblogoschat: | build-waku-librln build-waku-nat build-libchat logos_chat.nims
	echo -e $(BUILD_MSG) "$(LIBLOGOSCHAT)" && \
	$(ENV_SCRIPT) nim liblogoschat $(NIM_PARAMS) --path:src logos_chat.nims && \
	echo -e "\n\x1B[92mLibrary built successfully:\x1B[39m" && \
	echo "  $(shell pwd)/$(LIBLOGOSCHAT)"
ifeq ($(shell uname -s),Darwin)
	@cp vendor/libchat/target/release/liblibchat.dylib build/
	@# Fix install names so the dylibs are relocatable (no absolute paths)
	@install_name_tool -id @rpath/liblibchat.dylib build/liblibchat.dylib
	@echo "  $(shell pwd)/build/liblibchat.dylib"
else ifeq ($(shell uname -s),Linux)
	@cp vendor/libchat/target/release/liblibchat.so build/
	@echo "  $(shell pwd)/build/liblibchat.so"
endif

endif


