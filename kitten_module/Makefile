include $(PWD)/../.config

LDFLAGS += --whole-archive


EXTRA_CFLAGS  += -I$(PWD)/../palacios/include/ -include autoconf.h -DMODULE=1 -D__KERNEL__=1


v3vee-y := 	main.o \
		vm.o \
		palacios_stubs.o \
		kitten-exts.o \
		iface-pisces-console.o


#		iface-pisces-pci.o



v3vee-$(V3_CONFIG_FILE) += iface-pisces-file.o

#v3vee-$(V3_CONFIG_PCI_PASSTHROUGH) += iface-pci-passthrough.o

#v3vee-objs := $(v3vee-y)
obj-m := $(v3vee-y)

all:
	$(MAKE) -C $(V3_CONFIG_KITTEN_KERN) M=$(PWD) modules
	ar rcs ../libv3vee.a $(v3vee-y)


clean:
	$(MAKE) -C $(V3_CONFIG_KITTEN_KERN) M=$(PWD) clean

