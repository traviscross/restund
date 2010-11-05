#
# module.mk
#
# Copyright (C) 2010 Creytiv.com
#

MOD		:= mysql_ser
$(MOD)_SRCS	+= mysql_ser.c
$(MOD)_LFLAGS	+= -lmysqlclient

ifeq ($(ARCH),x86_64)
$(MOD)_LFLAGS	+= -L/usr/lib64/mysql
endif

ifneq ($(SYSROOT_ALT),)
CFLAGS		+= -I$(SYSROOT_ALT)/include/mysql5
$(MOD)_LFLAGS	+= -L$(SYSROOT_ALT)/lib/mysql5/mysql
ifneq ($(shell [ -d $(SYSROOT_ALT)/lib/mysql ] && echo 1),)
$(MOD)_LFLAGS	+= -L$(SYSROOT_ALT)/lib/mysql
endif
else
$(MOD)_LFLAGS	+= -L$(SYSROOT)/lib/mysql
endif

include mk/mod.mk
