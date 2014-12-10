#
# static.mk
#

src/static.c: $(BUILD) Makefile $(APP_MK) $(MOD_MK)
	@echo "  SH      $@"
	@echo "/* static.c - autogenerated by makefile */"  > $@
	@echo "#include <re_types.h>"  >> $@
	@echo "#include <re_mod.h>"  >> $@
	@echo ""  >> $@
	@for n in $(MODULES); do \
		echo "extern const struct mod_export exports_$${n};" >> $@ ; \
	done
	@echo ""  >> $@
	@echo "const struct mod_export *mod_table[] = {"  >> $@
	@for n in $(MODULES); do \
		echo "  &exports_$${n},"  >> $@  ; \
	done
	@echo "  NULL"  >> $@
	@echo "};"  >> $@
