/* 
   Palacios main control interface
   (c) Jack Lange, 2010
 */


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include <linux/io.h>

#include <linux/file.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>

#include <linux/version.h>
#include <linux/seq_file.h>

#include <palacios/vmm.h>

#include "palacios.h"
#include "mm.h"
#include "vm.h"
#include "numa.h"

#include "linux-exts.h"



MODULE_LICENSE("GPL");

// Module parameter
int cpu_list[V3_CONFIG_MAX_CPUS] = {[0 ... V3_CONFIG_MAX_CPUS - 1] = 0}; /* Array of CPU ids to be enabled during initialization */
int cpu_list_len      = 0;
module_param_array(cpu_list, int, &cpu_list_len, 0644);
MODULE_PARM_DESC(cpu_list, "Comma-delimited list of CPUs that Palacios will run on");

int active_cpu_list[V3_CONFIG_MAX_CPUS] = {[0 ... V3_CONFIG_MAX_CPUS - 1] = 0}; /* Array of CPUs that are currently enabled */



static struct v3_guest * guest_map[MAX_VMS] = {[0 ... MAX_VMS - 1] = 0};

static int               v3_major_num       = 0;
struct class           * v3_class           = NULL;
static struct cdev       ctrl_dev;
struct proc_dir_entry  * palacios_proc_dir  = NULL;



static int 
register_vm(struct v3_guest * guest) 
{
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
v3_dev_ioctl(struct file  * filp,
	     unsigned int   ioctl, 
	     unsigned long  arg) 
{
    void __user * argp = (void __user *)arg;
    DEBUG("V3 IOCTL %d\n", ioctl);


    switch (ioctl) {
	case V3_CREATE_GUEST:{
	    int vm_minor = 0;
	    struct v3_guest_img   user_image;
	    struct v3_guest     * guest = palacios_kmalloc(sizeof(struct v3_guest), GFP_KERNEL);

	    if (IS_ERR(guest)) {
		ERROR("Palacios: Error allocating Kernel guest_image\n");
		return -EFAULT;
	    }

	    memset(guest, 0, sizeof(struct v3_guest));

	    v3_lnx_printk("Palacios: Creating V3 Guest...\n");

	    vm_minor = register_vm(guest);

	    if (vm_minor == -1) {
		ERROR("Palacios Error: Too many VMs are currently running\n");
		goto out_err;
	    }

	    guest->vm_dev = MKDEV(v3_major_num, vm_minor);

	    if (copy_from_user(&user_image, argp, sizeof(struct v3_guest_img))) {
		ERROR("Palacios Error: copy from user error getting guest image...\n");
		goto out_err1;
	    }

	    guest->img_size = user_image.size;

	    DEBUG("Palacios: Allocating kernel memory for guest image (%llu bytes)\n", user_image.size);
	    guest->img = vmalloc(guest->img_size);

	    if (IS_ERR(guest->img)) {
		ERROR("Palacios Error: Could not allocate space for guest image\n");
		goto out_err1;
	    }

	    if (copy_from_user(guest->img, user_image.guest_data, guest->img_size)) {
		ERROR("Palacios: Error loading guest data\n");
		goto out_err2;
	    }	   

	    strncpy(guest->name, user_image.name, 127);

	    INIT_LIST_HEAD(&(guest->exts));

	    if (create_palacios_vm(guest) == -1) {
		ERROR("Palacios: Error creating guest\n");
		goto out_err2;
	    }

	    return vm_minor;


out_err2:
            vfree(guest->img);
out_err1:
            guest_map[vm_minor] = NULL; 
out_err:
            palacios_kfree(guest);

            return -1;

	    break;
	}
	case V3_FREE_GUEST: {
	    unsigned long     vm_idx = arg;
	    struct v3_guest * guest  = guest_map[vm_idx];

	    if (!guest) {
		ERROR("No VM at index %ld\n",vm_idx);
		return -1;
	    }

	    v3_lnx_printk("Freeing VM (%s) (%p)\n", guest->name, guest);

	    if (free_palacios_vm(guest) < 0) { 
		ERROR("Cannot free guest at index %ld\n", vm_idx);
		return -1;
	    }

	    guest_map[vm_idx] = NULL;
	    break;
	}
	case V3_ADD_CPU: {
	    int cpu_id = (int)arg;
	    int ret    = 0;

	    ret = v3_add_cpu(cpu_id);

	    if (ret == 1) {
		active_cpu_list[cpu_id] = 1;
	    } else if (ret < 0) {
                printk(KERN_ERR "Error adding CPU %d to Palacios\n", cpu_id);
	    }

	    return ret;
	    break;
	}
	case V3_REMOVE_CPU: {
	    int cpu_id = (int)arg;
	    int ret    = 0;

	    ret = v3_remove_cpu(cpu_id);

	    if (ret == 1) {
		active_cpu_list[cpu_id] = 0;
	    } else if (ret < 0) {
                printk(KERN_ERR "Error adding CPU %d to Palacios\n", cpu_id);
	    }

	    return ret;
	    break;
	}
	case V3_ADD_MEM: {
	    struct v3_mem_region mem;
	    
	    memset(&mem, 0, sizeof(struct v3_mem_region));
	    
	    if (copy_from_user(&mem, argp, sizeof(struct v3_mem_region))) {
		ERROR("copy from user error getting mem_region...\n");
		return -EFAULT;
	    }

	    v3_lnx_printk("Adding %llu pages to Palacios memory\n", mem.num_pages);

	    if (add_palacios_memory(mem.base_addr, mem.num_pages) == -1) {
		ERROR("Error adding memory to Palacios\n");
		return -EFAULT;
	    }

	    break;
	}
	case V3_REMOVE_MEM: {
	    uintptr_t base_addr = (uintptr_t)arg;


	    if (remove_palacios_memory(base_addr) == -1) {
		ERROR("Could not remove memory block (base_addr=%p) from Palacios\n", 
		      (void *)base_addr);
		return -EFAULT;
	    }

	    break;
	}
        case V3_SHUTDOWN: {
	    /* With Linux this is handled by module exit */
	    break;
        }

	default: {
	    struct global_ctrl * ctrl = get_global_ctrl(ioctl);
	    
	    if (ctrl) {
		return ctrl->handler(ioctl, arg);
	    }

	    WARNING("\tUnhandled global ctrl cmd: %d\n", ioctl);

	    return -EINVAL;
	}
    }

    return 0;
}



static struct file_operations v3_ctrl_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = v3_dev_ioctl,
    .compat_ioctl   = v3_dev_ioctl,
};


/* PROC FILE OUTPUT */


/* This is OK, because at least for now there is no way we will exceed 4KB of data in the file. 
 * If we ever do, we will need to implement a full seq_file implementation
 */
static int 
vm_seq_show(struct seq_file * s, 
	    void            * v) 
{
    int num_vms = 0;
    int i = 0;
    
    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i]) num_vms++;
    }
    
    seq_printf(s, "V3 GUESTS (%d)\n", num_vms);

    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i]) {
	    seq_printf(s, "%s: [vm_id=%d]\n", 
		       guest_map[i]->name, i);

	}
    }

    return 0;
}



static int vm_proc_open(struct inode * inode, struct file * filp) {
    return single_open(filp, vm_seq_show, NULL);
    
}

static const struct file_operations vm_proc_ops = {
    .owner   = THIS_MODULE,
    .open    = vm_proc_open, 
    .read    = seq_read, 
    .llseek  = seq_lseek,
    .release = single_release,
};


static int 
cpu_seq_show(struct seq_file * s, 
	    void            * v) 
{
    int i;
    int * cpu_arr = NULL;
    int   cpu_cnt = 0;
    
    cpu_arr = v3_get_cpu_usage(&cpu_cnt);

    if (!cpu_arr) return -EFAULT;

    for (i = 0; i < V3_CONFIG_MAX_CPUS; i++) {
	if (active_cpu_list[i]) {
	    seq_printf(s, "CPU %d: enabled (%d vcores)\n", i, cpu_arr[i]);
	}
    }


    palacios_kfree(cpu_arr);

    return 0;
}



static int cpu_proc_open(struct inode * inode, struct file * filp) {
    return single_open(filp, cpu_seq_show, NULL);
    
}

static const struct file_operations cpu_proc_ops = {
    .owner   = THIS_MODULE,
    .open    = cpu_proc_open, 
    .read    = seq_read, 
    .llseek  = seq_lseek,
    .release = single_release,
};



/*** END PROC File functions */


static int __init 
v3_init(void) 
{
    dev_t dev = MKDEV(0, 0); // We dynamicallly assign the major number
    int   ret = 0;


    palacios_proc_dir = proc_mkdir("v3vee", NULL);

    if (palacios_init_mm() == -1) {
	ERROR("Error initializing memory subsystem\n");
	palacios_deinit_mm();
	return -1;
    }

    // Initialize Palacios
    palacios_vmm_init();

    palacios_init_numa();

    init_global_ctrls();
    // initialize extensions
    init_lnx_extensions();


    v3_class = class_create(THIS_MODULE, "vms");
    if (IS_ERR(v3_class)) {
	ERROR("Failed to register V3 VM device class\n");
	return PTR_ERR(v3_class);
    }

    v3_lnx_printk("intializing V3 Control device\n");

    ret = alloc_chrdev_region(&dev, 0, MAX_VMS + 1, "v3vee");

    if (ret < 0) {
	ERROR("Error registering device region for V3 devices\n");
	goto failure2;
    }

    v3_major_num = MAJOR(dev);
    dev          = MKDEV(v3_major_num, MAX_VMS + 1);

    
    DEBUG("Creating V3 Control device: Major %d, Minor %d\n", v3_major_num, MINOR(dev));

    cdev_init(&ctrl_dev, &v3_ctrl_fops);
    ctrl_dev.owner = THIS_MODULE;
    ctrl_dev.ops   = &v3_ctrl_fops;
    cdev_add(&ctrl_dev, dev, 1);
    
    device_create(v3_class, NULL, dev, NULL, "v3vee");

    if (ret != 0) {
	ERROR("Error adding v3 control device\n");
	goto failure1;
    }



    if (palacios_proc_dir) {
	struct proc_dir_entry * entry = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	entry = create_proc_entry("v3-guests", 0444, palacios_proc_dir);

        if (entry) {
	    entry->proc_fops = &vm_proc_ops;
	    v3_lnx_printk("/proc/v3vee/v3-guests successfully created\n");
	}

	entry = create_proc_entry("v3-cpus", 0444, palacios_proc_dir);

        if (entry) {
	    entry->proc_fops = &cpu_proc_ops;
	    v3_lnx_printk("/proc/v3vee/v3-cpus successfully created\n");
	}
#else 
	entry = proc_create_data("v3-guests", 0444, palacios_proc_dir, &vm_proc_ops, NULL);
	entry = proc_create_data("v3-cpus",   0444, palacios_proc_dir, &cpu_proc_ops, NULL);
#endif

	if (!entry) {
	    ERROR("Could not create proc entry (%s)\n", "v3-guests");
	    goto failure1;
	}

	
    } else {
	ERROR("Could not create proc entry\n");
	goto failure1;
    }

    return 0;

 failure1:
    unregister_chrdev_region(MKDEV(v3_major_num, 0), MAX_VMS + 1);
 failure2:
    class_destroy(v3_class);

    return ret;
}


static void __exit 
v3_exit(void) 
{
    struct v3_guest * guest = NULL;
    dev_t dev;
    int   i = 0;

    /* Stop and free any running VMs */ 
    for (i = 0; i < MAX_VMS; i++) {
	if (guest_map[i] != NULL) {
                guest = (struct v3_guest *)guest_map[i];

                if (v3_stop_vm(guest->v3_ctx) < 0) {
                        ERROR("Couldn't stop VM %d\n", i);
		}

                free_palacios_vm(guest);
                guest_map[i] = NULL;
	}
    }

    dev = MKDEV(v3_major_num, MAX_VMS + 1);

    v3_lnx_printk("Removing V3 Control device\n");

    unregister_chrdev_region(MKDEV(v3_major_num, 0), MAX_VMS + 1);

    cdev_del(&ctrl_dev);

    device_destroy(v3_class, dev);
    class_destroy(v3_class);



    palacios_vmm_exit();





    deinit_lnx_extensions();
    deinit_global_ctrls();

    palacios_deinit_mm();

    remove_proc_entry("v3-guests", palacios_proc_dir);
    remove_proc_entry("v3-cpus",   palacios_proc_dir);
    remove_proc_entry("v3vee",     NULL);


    {
	/*
	 * Simple Memory leak detection
	 * We count the number of alloc/free operations, and compare them here 
	 */

	extern u32 pg_allocs;
	extern u32 pg_frees;
	extern u32 mallocs;
	extern u32 frees;

	if ((frees    != mallocs) ||
	    (pg_frees != pg_allocs)) {

	    ERROR("Memory Leak Detected!!!\n");
	    ERROR("\t-- Mallocs = %d, Frees = %d\n", mallocs, frees);
	    ERROR("\t-- Page Allocs = %d, Page Frees = %d\n", pg_allocs, pg_frees);
	}
    }
}



module_init(v3_init);
module_exit(v3_exit);
