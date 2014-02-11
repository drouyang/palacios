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

#include <lwk/kthread.h>
#include <arch/unistd.h>
#include <arch/vsyscall.h>

#include <arch/pisces/pisces_file.h>

#include "palacios.h"
#include "kitten-exts.h"
#include "vm.h"

struct vm_path {
    char file_name[256];
    char vm_name[128];
} __attribute__((packed));

static struct v3_guest * guest_map[MAX_VMS] = {[0 ... MAX_VMS - 1] = 0};
static char * options = NULL;




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



static long
palacios_ioctl(struct file * filp,
	       unsigned int ioctl, unsigned long arg) 
{
    void __user * argp = (void __user *)arg;

    printk("Palacios IOCTL: %d\n", ioctl);

    switch (ioctl) {
	case V3_CREATE_GUEST: {
	    struct vm_path guest_path;
	    struct v3_guest * guest = NULL;
	    u64 img_size = 0;
	    u64 file_handle = 0;
	    u8 * img_ptr = NULL;
	    int guest_id = 0;

	    printk("Creating Guest IOCTL\n");

	    memset(&guest_path, 0, sizeof(struct vm_path));
	    
	    if (copy_from_user(&guest_path, argp, sizeof(struct vm_path))) {		
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
		kmem_free(guest);
		return -1;
	    }


	    guest->guest_id = guest_id;

	    file_handle = pisces_file_open(guest_path.file_name, O_RDONLY);
    
	    if (file_handle == 0) {
		printk("Error: Could not open VM image file (%s)\n", guest_path.file_name);
		return -1;
	    }
    
	    img_size = pisces_file_size(file_handle);
    
	    printk("Image size=%llu\n", img_size);
    
    
	    {
		struct pmem_region result;
		int status = 0;
	
		status = pmem_alloc_umem(img_size, 0, &result);
	
		if (status) {
		    printk("Error allocating User memory\n");
		    return -1;
		}
	
		status = pmem_zero(&result);
	
		if (status) {
		    printk("Error zeroing User memory\n");
		    return -1;
		}
	
		img_ptr = __va(result.start);
	    }
    
    
	    //	    img_ptr = kmem_alloc(img_size);
    
	    printk("Reading Image File to %p\n", img_ptr);
    
	    pisces_file_read(file_handle, img_ptr, img_size, 0);
	    pisces_file_close(file_handle);

	    guest->img = img_ptr;
	    guest->img_size = img_size;
	    strncpy(guest->name, guest_path.vm_name, 128);

	    palacios_create_vm(guest);

	    return guest_id;

	}
	case V3_ADD_CPU: {
	    int cpu_id = (int)arg;
	    
	    if (v3_add_cpu(cpu_id) != 0) {
		printk(KERN_ERR "Error adding CPU %d to Palacios\n", cpu_id);
		return -EFAULT;
	    }

	    return 0;

	}
	default:
	    {
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


extern void v3_print_guest_state_all(struct v3_vm_info * vm);
static void
dbg_handler(struct pt_regs * regs, unsigned int vector) {


	printk("DBG Handler\n");

	v3_print_guest_state_all(guest_map[0]->v3_ctx);

	return;
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

	kfs_create("/palacios-cmd", 
		   NULL, 
		   &palacios_ctrl_fops,
		   0777, 
		   NULL, 0);


	set_idtvec_handler(169, dbg_handler);

	return 0;
}

DRIVER_INIT( "module", palacios_init );
DRIVER_PARAM(options, charp);



