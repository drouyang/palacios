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

	    INIT_LIST_HEAD(&(guest->exts));

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


	    init_vm_extensions(guest);

	    guest->v3_ctx = v3_create_vm(img_ptr, guest, guest_path.vm_name);

	    printk("Created VM (id=%d)\n", guest_id);

	    return guest_id;
	}
	case V3_VM_LAUNCH: {
	    int guest_id = (int)arg;
	    struct v3_guest * guest = guest_map[guest_id];
	    unsigned int mask = 0;

	    printk("STarting VM to Palacios %d\n", guest_id);
	
	    if (!guest) {
		printk("No Guest registered at %d\n", guest_id);
		return -1;
	    }

	    mask =~ ((((signed int)1 << (sizeof(unsigned int) * 8 - 1)) >> (sizeof(unsigned int) * 8 - 1 )) << cpus_weight(cpu_online_map));


	    return v3_start_vm(guest->v3_ctx, mask);
	    break;
	}
	default:
	    return -EINVAL;
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


	return 0;
}

DRIVER_INIT( "module", palacios_init );
DRIVER_PARAM(options, charp);
