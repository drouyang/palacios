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
#include <lwk/fdTable.h>
#include <lwk/poll.h>
#include <lwk/kfs.h>
#include <lwk/proc_fs.h>

#include <lwk/kthread.h>
#include <arch/unistd.h>
#include <arch/vsyscall.h>


#include "palacios.h"
#include "kitten-exts.h"
#include "vm.h"


static struct v3_guest * guest_map[MAX_VMS] = {[0 ... MAX_VMS - 1] = 0};
static char            * options = NULL;




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


static int free_vm(unsigned long vm_idx) {
    struct pmem_region   query;
    struct pmem_region   result;
    struct v3_guest    * guest  = guest_map[vm_idx];

    if (!guest) {
	ERROR("No VM at index %ld\n", vm_idx);
	return -1;
    }
    
    v3_lwk_printk("Freeing VM (%s) (%p)\n", guest->name, guest);

    if (palacios_free_vm(guest) < 0) { 
	ERROR("Cannot free guest VM (%s)\n", guest->name);
	return -1;
    }

    guest_map[vm_idx] = NULL;

    /* Free Guest Image */
    {
	pmem_region_unset_all(&query);
		
	query.start            = (uintptr_t)__pa(guest->img);
	query.end              = (uintptr_t)__pa(guest->img) + guest->img_size;
	query.allocated        = true;
	query.allocated_is_set = true;

	if (pmem_query(&query, &result) == 0) {

	    result.allocated       = false;
		
	    if (pmem_update(&result) != 0) {
		ERROR("Could not Free guest image from PMEM\n");
	    }
	} else {
	    ERROR("Could not find guest image in PMEM\n");
	}
    }

    kmem_free(guest);

    return 0;
}

static long
palacios_ioctl(struct file  * filp,
	       unsigned int   ioctl, 
	       unsigned long  arg) 
{
    void __user * argp = (void __user *)arg;

    printk("Palacios IOCTL: %d\n", ioctl);

    switch (ioctl) {
	case V3_CREATE_GUEST: {
	    struct v3_guest_img   guest_image;
	    struct v3_guest * guest = NULL;
	    struct pmem_region result;
		
	    int   guest_id    = 0;

	    printk("Creating Guest IOCTL\n");

	    
	    memset(&guest_image, 0, sizeof(struct v3_guest_img));
	    
	    if (copy_from_user(&guest_image, argp, sizeof(struct v3_guest_img))) {
		printk(KERN_ERR "Palacios: Error Could not copy guest path from userspace\n");
		return -EFAULT;
	    }

	    guest = kmem_alloc(sizeof(struct v3_guest));
 
	    if (guest == NULL) {
		printk(KERN_ERR "Palacios: Error allocating Kernel guest\n");
		return -EFAULT;
	    }

	    memset(guest, 0, sizeof(struct v3_guest));
	    

	    guest_id =  register_vm(guest);

	    if (guest_id == -1) {
		printk("Error registering VM in Kitten\n");
		goto out_err;
	    }


	    guest->guest_id = guest_id;


	    guest->img_size = guest_image.size;


	    printk("Image size=%u\n", guest->img_size);
    
    
	    {
		int status = 0;
	
		status = pmem_alloc_umem(guest->img_size, 0, &result);
	
		if (status) {
		    printk("Error allocating User memory\n");
		    goto out_err1;
		}
	
		status = pmem_zero(&result);
	
		if (status) {
		    printk("Error zeroing User memory\n");
		    goto out_err2;
		}
	
		guest->img = __va(result.start);
	    }
    
    
	    if (copy_from_user(guest->img, guest_image.guest_data, guest->img_size)) {
		printk(KERN_ERR "Palacios: Error copying in guest image\n");
		goto out_err2;
	    }
    
	    printk("Reading Image File to %p\n", guest->img);
    
	    strncpy(guest->name, guest_image.name, 128);

	    if (palacios_create_vm(guest) == -1) {
		printk("Error: Could not create VM (%s)\n", guest->name);
		goto out_err2;
	    }

	    return guest_id;

	    
out_err2:
	    pmem_free_umem(&result);
out_err1:
	    guest_map[guest_id] = NULL;
out_err:
	    kmem_free(guest);

	    return -1;

	}
	case V3_FREE_GUEST: {
	    unsigned long     vm_idx = arg;


	    return free_vm(vm_idx);
	    break;

	}
	case V3_ADD_CPU: {
	    int cpu_id = (int)arg;
	    
	    if (v3_add_cpu(cpu_id) != 1) {
		printk(KERN_ERR "Error adding CPU %d to Palacios\n", cpu_id);
		return -EFAULT;
	    }

	    return 0;

	}
	case V3_REMOVE_CPU: {
	    int cpu_id = (int)arg;

	    if (v3_remove_cpu(cpu_id) != 0) {
                printk(KERN_ERR "Error adding CPU %d to Palacios\n", cpu_id);
                return -1;
	    }

	    break;
	}
	case V3_SHUTDOWN: {
	    unsigned long i = 0;

	    for (i = 0; i < MAX_VMS; i++) {
		if (guest_map[i] != NULL) {
		    struct v3_guest * guest = guest_map[i];

		    if (v3_stop_vm(guest->v3_ctx) < 0) {
			printk(KERN_ERR "Couldn't stop VM %lu\n", i);
		    }

		    free_vm(i);
		}
	    }
	    

	    if (Shutdown_V3() == -1) {
		printk(KERN_ERR "Error: Could not shutdown palacios\n");
		return -1;
	    }
	    
	
	    break;
	}
	default: {
	    struct global_ctrl * ctrl = get_global_ctrl(ioctl);
	    
	    if (ctrl) {
		return ctrl->handler(ioctl, arg);
	    }
	    
	    printk(KERN_WARNING "\tUnhandled global ctrl cmd: %d\n", ioctl);
	    
	    return -EINVAL;
	}
    }


    return 0;
}


static struct kfs_fops palacios_ctrl_fops = {
    //	.open = palacios_open, 
    //	.write = palacios_write,
    //	.read = palacios_read,
    //	.poll = palacios_poll, 
    //	.close = palacios_close,
    .unlocked_ioctl = palacios_ioctl,
};



static int
get_vm_proc_data(struct file * file, void * private)
{
    int num_vms = 0;
    int i = 0;
    
    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i]) num_vms++;
    }
    
    proc_sprintf(file, "V3 GUESTS (%d)\n", num_vms);

    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i]) {
	    proc_sprintf(file, "%s: [vm_id=%d]\n", 
		       guest_map[i]->name, i);

	}
    }

    return 0;
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

	init_lwk_extensions();

	//	syscall_register(__NR_v3_start_guest, (syscall_ptr_t) sys_v3_start_guest);


	printk("creating palacios command file\n");

	kfs_create(V3_CMD_PATH, 
		   NULL, 
		   &palacios_ctrl_fops,
		   0777, 
		   NULL, 0);

	proc_mkdir(V3_PROC_PATH);

	create_proc_file(V3_PROC_PATH "/v3-guests", get_vm_proc_data, NULL);

	return 0;
}

DRIVER_INIT( "module", palacios_init );
DRIVER_PARAM(options, charp);



