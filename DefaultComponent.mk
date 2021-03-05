SRCS := $(wildcard *.c)
DEPS := $(patsubst %.c,%.d,$(SRCS))

RELOBJS = $(patsubst %.c,$(RELBUILDDIR)/%.o,$(SRCS))
DBGOBJS = $(patsubst %.c,$(DBGBUILDDIR)/%.o,$(SRCS))
DBGROBJS = $(patsubst %.c,$(DBGRBUILDDIR)/%.o,$(SRCS))
TESTOBJS = $(patsubst %.c,$(TESTBUILDDIR)/%.o,$(SRCS))

RELDEPS = $(addprefix $(RELBUILDDIR)/,$(DEPS))
DBGDEPS = $(addprefix $(DBGBUILDDIR)/,$(DEPS))
DBGRDEPS = $(addprefix $(DBGRBUILDDIR)/,$(DEPS))
TESTDEPS = $(addprefix $(TESTBUILDDIR)/,$(DEPS))

.PHONY: all test debug debugger release prep clean remake clean-hard

#   Top level general targets for a component.
#   Components do not need to block on the "test" target
all: prep
	$(MAKE) test
	$(MAKE) debug debugger release

prep:
	@mkdir -p $(RELBUILDDIR) $(DBGBUILDDIR) $(DBGRBUILDDIR) $(TESTBUILDDIR)

clean-hard: clean

clean:
	$(RM) $(RELOBJS) $(DBGOBJS) $(DBGROBJS) $(TESTOBJS) $(RELDEPS) $(DBGDEPS) $(DBGRDEPS) $(TESTDEPS)

remake:
	$(MAKE) clean
	$(MAKE) all

test: $(TESTOBJS)

debug: $(DBGOBJS)

debugger: $(DBGROBJS)

release: $(RELOBJS)

include $(ROOTDIR)/Objects.mk

