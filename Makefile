#	Common Makefile variables and recipes for all sub-components of the application

#   Standard Compiler Settings
CC              := gcc
WARNINGS        := -Wall -Werror -Wpedantic -Wextra
WARNINGS_IGNORE :=
CFLAGS          := -ansi $(WARNINGS) $(WARNINGS_IGNORE)
LIBTOOL         := ar -rcs
FMTTOOL         := $(shell which clang-format)

#   Define the flags for the various different end-result build targets
RELFLAGS  := $(CFLAGS) -O2 -DNDEBUG
DBGFLAGS  := $(CFLAGS) -g -O0 -DDEBUG
DBGRFLAGS := $(CFLAGS) -g -O0 -DDEBUG -DDEBUGGER
TESTFLAGS := $(CFLAGS) -g -O0 -DDEBUG -DDEBUGGER -DTESTING

#   Other shell command settings
RM    := rm -f
STRIP := strip -S -X

#   Common Variables
ROOTDIR      := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
SRCROOTDIR   := $(ROOTDIR)/src
BUILDROOTDIR := $(ROOTDIR)/build
OUTROOTDIR   := $(ROOTDIR)/products
TARGET       := libcrypto
TARGETSUFFIX := .a
TESTSUFFIX   := .out

#   Applicaton sub-components
#   Add in and subfolders required to make the full application here.
COMPONENTS     := src/cipher
COMPONENTS     += src/AES src/AES/context src/AES/round
COMPONENTS     += src/ChaCha src/ChaCha/context src/ChaCha/round
TESTCOMPONENTS := src

#   Release Build Settings
RELBUILDDIR := $(BUILDROOTDIR)/release
RELOUTDIR   := $(OUTROOTDIR)/release
RELOBJS      = $(wildcard $(RELBUILDDIR)/*.o)
RELEXE      := $(RELOUTDIR)/$(TARGET)$(TARGETSUFFIX)

#   Debug Build Settings
DBGBUILDDIR := $(BUILDROOTDIR)/debug
DBGOUTDIR   := $(OUTROOTDIR)/debug
DBGOBJS      = $(wildcard $(DBGBUILDDIR)/*.o)
DBGEXE      := $(DBGOUTDIR)/$(TARGET)-debug$(TARGETSUFFIX)

#   Debugger Build Settings
DBGRBUILDDIR := $(BUILDROOTDIR)/debugger
DBGROUTDIR   := $(OUTROOTDIR)/debugger
DBGROBJS      = $(wildcard $(DBGRBUILDDIR)/*.o)
DBGREXE      := $(DBGROUTDIR)/$(TARGET)-debugger$(TESTSUFFIX)

#   Test Build Settings
TESTBUILDDIR := $(BUILDROOTDIR)/testing
TESTOUTDIR   := $(OUTROOTDIR)/testing
TESTOBJS      = $(wildcard $(TESTBUILDDIR)/*.o)
TESTEXE      := $(TESTOUTDIR)/$(TARGET)-test$(TESTSUFFIX)

#   Export the specific compiler to use.
export CC

#   Export the source code formatter to use.
export FMTTOOL

#   Export the various directories so any and all sub-makes can put their objects in the correct directories.
export ROOTDIR RELBUILDDIR DBGBUILDDIR DBGRBUILDDIR TESTBUILDDIR

#   Export the compiler flags to use
export RELFLAGS DBGFLAGS DBGRFLAGS TESTFLAGS

#   Set up the .PHONY targets
.PHONY: all help prep release test debug debugger clean clean-hard remake $(TESTCOMPONENTS) $(COMPONENTS)

help: ## Show this help menu.
	@echo "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' | column -c2 -t -s :)"


#   Top level general targets
#   Ensure test completes before attempting any other targets, to ensure
#   the testing suite successfully exits.
all: prep ## Build and run the test suite, then the debugger, debug, and release targets.
	$(MAKE) test
	$(MAKE) debug debugger release

prep: ## Prepare the build and output directory trees.
	@mkdir -p $(RELBUILDDIR) $(RELOUTDIR) $(DBGBUILDDIR) $(DBGOUTDIR) $(DBGRBUILDDIR) $(DBGROUTDIR) $(TESTBUILDDIR) $(TESTOUTDIR)

clean-hard: clean ## Run clean, but also remove any and all executables and the dependency files.
	$(RM) $(RELEXE) $(DBGEXE) $(DBGREXE) $(TESTEXE)

clean: $(COMPONENTS) $(TESTCOMPONENTS) ## Remove any and all of the object files.

remake: prep ## Perform a clean then an all
	$(MAKE) clean
	$(MAKE) all

#	Sub-component Make arguments
$(COMPONENTS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

#	Sub-component Make arguments for testing mode
$(TESTCOMPONENTS):
	$(MAKE) -C $@ $(MAKECMDGOALS)


#   Testing Build Targets
test: prep $(TESTCOMPONENTS) $(COMPONENTS) ## Build and run the testing executable.
	$(CC) -o $(TESTEXE) $(TESTOBJS)
	$(TESTEXE)


#   Debug Build Targets
debug: prep $(COMPONENTS) ## Build the library with all of the debugging symbols enabled.
	$(LIBTOOL) $(DBGEXE) $(filter-out %test.o, $(DBGOBJS))


#   Debugger Build Targets
debugger: prep $(TESTCOMPONENTS) $(COMPONENTS) ## Build the library with debugging enabled and an entry point to the testing suite.
	$(CC) -o $(DBGREXE) $(DBGROBJS)


#   Release Build Targets
release: prep $(COMPONENTS) ## Build the library into a release mode, with debugging off, optimizations on, and the resulting library stripped.
	$(LIBTOOL) $(RELEXE) $(filter-out %test.o, $(RELOBJS))
	$(STRIP) $(RELEXE)