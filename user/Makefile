
#
# Build Static or Dynamic versions of the control utilities
#
#

include $(PWD)/../.config

USER_TOOLS_DIR = $(PWD)

CC = gcc
AR = ar

PETLIB := $(V3_CONFIG_PETLIB_PATH)

CFLAGS = -I../linux_module -I$(PETLIB) -L$(PETLIB)

ifdef V3_CONFIG_USER_STATIC
  CFLAGS += -static 
  CURSES_CFLAGS = -DNCURSES_STATIC 
endif

#
# Executables that implement core functionality
#


execs-y := 	v3_mem \
		v3_cpu \
		v3_free \
		v3_launch \
		v3_stop \
		v3_pause \
		v3_continue \
		v3_core_move \
		v3_debug \
		v3_create



execs-$(V3_EXPERIMENTAL) += v3_simulate

execs-$(V3_CONFIG_CONSOLE) += 	v3_cons \
				v3_cons_sc \

execs-$(V3_CONFIG_STREAM)  += v3_stream
execs-$(V3_CONFIG_HOST_PCI) += v3_pci


execs-$(V3_CONFIG_LIVE_MIGRATION) += 	v3_send \
					v3_receive

execs-$(V3_CONFIG_CHECKPOINT) += 	v3_save \
					v3_load


libs-y := 	libv3vee_user.a

libv3vee_user_objs :=	create.o \
			v3vee.o


CFILES = $(execs-y:%=%.c) 

build = \
	@if [ -z "$V" ]; then \
		echo '  [$1]	$@'; \
		$2; \
	else \
		echo '$2'; \
		$2; \
	fi

quiet-build = \
	@if [ -z "$V" ]; then \
		$1; \
	else \
		echo '$1'; \
		$1; \
	fi


% : %.c v3_ioctl.h $(libv3vee_user_objs)
	$(call build,CC,$(CC) $(CFLAGS) $< libv3vee_user.a $(PETLIB)/petlib.a  -o $@)


%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)


all: depend petlib $(libs-y) $(execs-y) 

libv3vee_user.a: $(libv3vee_user_objs)
	$(call build,AR,$(AR) rcs $@ $^)

petlib: $(PETLIB)/petlib.a

$(PETLIB)/petlib.a:
	make -C $(PETLIB)

#
# Most tools compile in a straightforward way
#

#include .dependencies



#
# Tools requiring specialized build processes
#
#

v3_cons: v3_cons.c v3_ioctl.h
	$(call build,CC,$(CC) $(CFLAGS) $< -lcurses -ltinfo -o $@)

v3_cons_sc: v3_cons_sc.c v3_ioctl.h
	$(call build,CC,$(CC) $(CFLAGS)  $< -lcurses -ltinfo -o $@)



#
# Cleanup and dependency builds are automated
#


clean-cmd = rm -f $(wildcard $(execs-y) $(execs-) $(libs-y) $(libs-) *.o)


clean:
	$(call quiet-build,$(clean-cmd))
	make -C $(PETLIB) clean

depend:
	$(call quiet-build,$(CC) -MM $(CFILES) -I../linux_module > .dependencies)
