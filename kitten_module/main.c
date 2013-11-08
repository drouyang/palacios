/* 
   Palacios main control interface for Kitten
   (c) Jack Lange, 2013
 */

#include <lwk/kernel.h>
#include <lwk/smp.h>
#include <lwk/pmem.h>
#include <lwk/string.h>
#include <arch/proto.h>
#include <lwk/cpuinfo.h>
#include <lwk/driver.h>

#include <lwk/kthread.h>
#include <arch/unistd.h>
#include <arch/vsyscall.h>


#include "palacios.h"


//static struct v3_guest * guest_map[MAX_VMS] = {[0 ... MAX_VMS - 1] = 0};
static char * options = NULL;



/*
static int register_vm(struct v3_guest * guest) {
    int i = 0;

    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i] == NULL) {
	    guest_map[i] = guest;
	    return i;
	}
    }

    return -1;
}

*/

/**
 * Starts a guest operating system.
 */
static int
palacios_run_guest(void *arg)
{
	unsigned int mask = 0;
	struct v3_vm_info * vm_info = v3_create_vm(NULL, NULL, NULL);
	
	if (!vm_info) {
		printk(KERN_ERR "Could not create guest context\n");
		return -1;
	}


	printk(KERN_INFO "Starting Guest OS...\n");

	// set the mask to inclue all available CPUs
	// we assume we will start on CPU 0
	//	mask=~((((signed int)1<<(sizeof(unsigned int)*8-1))>>(sizeof(unsigned int)*8-1))<<cpus_weight(cpu_online_map));

	return v3_start_vm(vm_info, mask);
}

/**
 * Kicks off a kernel thread to start and manage a guest operating system.
 */
static int
sys_v3_start_guest(
	paddr_t			iso_start,
	size_t			iso_size
)
{
	if (current->uid != 0)
		return -EPERM;


	return palacios_run_guest(0);
}



/**
 * Initialize the Palacios hypervisor.
 */
static int
palacios_init(void)
{

	printk(KERN_INFO "---- Initializing Palacios hypervisor support\n");
	printk(KERN_INFO "cpus_weight(cpu_online_map)=0x%x\n", cpus_weight(cpu_online_map));

	palacios_vmm_init(options);

	syscall_register(__NR_v3_start_guest, (syscall_ptr_t) sys_v3_start_guest);

	return 0;
}

DRIVER_INIT( "module", palacios_init );
DRIVER_PARAM(options, charp);
