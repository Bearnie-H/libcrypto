
SRCS := $(wildcard *.c)
DEPS := $(patsubst %.c,%.d,$(SRCS))


#   Filter out any files of the form: *_test.c from the
#   release and debug targets. No point in compiling files that are intended to
#   be excluded from useable output builds.

RELOBJS = $(patsubst %.c,$(RELBUILDDIR)/%.o,$(filter-out %test.c, $(SRCS)))
DBGOBJS = $(patsubst %.c,$(DBGBUILDDIR)/%.o,$(filter-out %test.c, $(SRCS)))
DBGROBJS = $(patsubst %.c,$(DBGRBUILDDIR)/%.o,$(SRCS))
TESTOBJS = $(patsubst %.c,$(TESTBUILDDIR)/%.o,$(SRCS))

RELDEPS = $(addprefix $(RELBUILDDIR)/,$(filter-out %test.d, $(DEPS)))
DBGDEPS = $(addprefix $(DBGBUILDDIR)/,$(filter-out %test.d, $(DEPS)))
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
	$(RM) $(RELOBJS) $(DBGOBJS) $(DBGROBJS) $(TESTOBJS)
	$(RM) $(RELDEPS) $(DBGDEPS) $(DBGRDEPS) $(TESTDEPS)

remake:
	$(MAKE) clean
	$(MAKE) all

test: $(TESTOBJS)

debug: $(DBGOBJS)

debugger: $(DBGROBJS)

release: $(RELOBJS)

include $(ROOTDIR)/Objects.mk

