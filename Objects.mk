
$(TESTBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(TESTFLAGS) -o $@ $<

$(DBGBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(DBGFLAGS) -o $@ $<

$(DBGRBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(DBGRFLAGS) -o $@ $<

$(RELBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(RELFLAGS) -o $@ $<

