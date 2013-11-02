include $(PWD)/../.config

LDFLAGS += --whole-archive  --script=$(PWD)/ld.cmd


EXTRA_CFLAGS  += -I$(PWD)/../palacios/include/ -include autoconf.h -DMODULE=1 -D__KERNEL__=1


v3vee-y := 	palacios_stubs.o 

#v3vee-objs := $(v3vee-y) ../libv3vee.a

#obj-m := v3vee.o




all:
	$(MAKE) -C $(V3_CONFIG_KITTEN_KERN) M=$(PWD) modules
	ar rcs ../libv3vee $(v3vee-y)


clean:
	$(MAKE) -C $(V3_CONFIG_KITTEN_KERN) M=$(PWD) clean

