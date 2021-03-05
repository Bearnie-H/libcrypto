-include $(RELDEPS)
-include $(DBGDEPS)
-include $(DBGRDEPS)
-include $(TESTDEPS)

$(TESTBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(TESTFLAGS) -o $@ $< -MMD -MP

$(DBGBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(DBGFLAGS) -o $@ $< -MMD -MP

$(DBGRBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(DBGRFLAGS) -o $@ $<  -MMD -MP

$(RELBUILDDIR)/%.o : %.c
ifdef FMTTOOL
	$(FMTTOOL) -i $<
endif
	$(CC) -c $(RELFLAGS) -o $@ $< -MMD -MP

