
#
# Build Static or Dynamic versions of the control utilities
#
#

include $(PWD)/../.config


ifdef V3_CONFIG_LINUX_USER_STATIC
  CFLAGS += -static 
  CURSES_CFLAGS = -DNCURSES_STATIC 

endif


CC = gcc
AR = ar

PETLIB := ./petlib

CFLAGS += -I../linux_module -I$(PETLIB) -L$(PETLIB)

#
# Executables that implement core functionality
#


execs-y := 	v3_mem \
		v3_mem_free \
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
				v3_monitor

execs-$(V3_CONFIG_STREAM)  += v3_stream
execs-$(V3_CONFIG_KEYED_STREAM) += 	v3_user_keyed_stream_example \
					v3_user_keyed_stream_file


execs-$(V3_CONFIG_HOST_DEVICE) +=	v3_os_debug \
					v3_user_host_dev_example

execs-$(V3_CONFIG_HOST_PCI) += v3_pci


execs-$(V3_CONFIG_HOST_HYPERCALL) += v3_hypercall
execs-$(V3_CONFIG_EXT_ENV_INJECT) += v3_env_inject
execs-$(V3_CONFIG_EXT_CODE_INJECT) += v3_top_inject
execs-$(V3_CONFIG_EXT_SELECTIVE_SYSCALL_EXIT) += v3_syscall
execs-$(V3_CONFIG_EXT_MACH_CHECK) += v3_inject_ecc_scrubber_mce 

execs-$(V3_CONFIG_LIVE_MIGRATION) += 	v3_send \
					v3_receive

execs-$(V3_CONFIG_CHECKPOINT) += 	v3_save \
					v3_load


libs-y := 	ezxml.a 



libs-$(V3_CONFIG_HOST_DEVICE) += v3_user_host_dev.a
libs-$(V3_CONFIG_KEYED_STREAM) += v3_user_keyed_stream.a

CFILES = $(execs-y:%=%.c) $(libs-y:%.a=%.c) 

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




all: depend petlib $(libs-y) $(execs-y) 

petlib: $(PETLIB)/petlib.a

$(PETLIB)/petlib.a:
	make -C $(PETLIB)

#
# Most tools compile in a straightforward way
#

include .dependencies


% : %.c v3_ctrl.h
	$(call build,CC,$(CC) $(CFLAGS) $< $(PETLIB)/petlib.a -o $@)


%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)

#
# Tools requiring specialized build processes
#
#

v3_cons: v3_cons.c v3_ctrl.h
	$(call build,CC,$(CC) $(CFLAGS) $< -lcurses -o $@)

v3_cons_sc: v3_cons_sc.c v3_ctrl.h
	$(call build,CC,$(CC) $(CFLAGS)  $< -lcurses -o $@)

v3_create: v3_create.c ezxml.a v3_ctrl.h
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@)



v3_os_debug: v3_os_debug.c v3_user_host_dev.a
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@)

v3_user_host_dev_example : v3_user_host_dev_example.c v3_user_host_dev.a
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@)



v3_user_keyed_stream_file : v3_user_keyed_stream_file.c v3_user_keyed_stream.a
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@)

v3_user_keyed_stream_example : v3_user_keyed_stream_example.c v3_user_keyed_stream.a
	$(call build,CC,$(CC) $(CFLAGS) $^  -o $@)


#
# Cleanup and dependency builds are automated
#


clean-cmd = rm -f $(wildcard $(execs-y) $(execs-) $(libs-y) $(libs-) *.o)


clean:
	$(call quiet-build,$(clean-cmd))
	make -C $(PETLIB) clean

depend:
	$(call quiet-build,$(CC) -MM $(CFILES) -I../linux_module > .dependencies)
