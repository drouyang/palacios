/* 
 * Kitten based Palacios VM interface
 * (c) 2013, Jack Lange (jacklange@cs.pitt.edu)
 */

#include <lwk/kfs.h>
#include <arch/uaccess.h>
#include <arch/apic.h>

#include "palacios.h"
#include "kitten-exts.h"

static long
vm_ioctl(struct file * filp,
	 unsigned int cmd, unsigned long arg) 
{
    struct v3_guest * guest = filp->inode->priv;
    //  void __user * argp = (void __user *)arg;

    printk("VM IOCTL: %d (guest=%p)\n", cmd, guest);

    switch (cmd) {
	case V3_VM_LAUNCH: {
	    unsigned int mask = 0;

	    printk("Starting Palacios VM (VM=%d)\n", guest->guest_id);
	
	    if (!guest) {
		printk("No Guest registered at %d\n", guest->guest_id);
		return -1;
	    }

	    mask = (1 << (cpus_weight(cpu_online_map))) - 1;


	    return v3_start_vm(guest->v3_ctx, mask);
	    break;
	}
	default: {
	    return call_guest_ctrl(guest, cmd, arg);
	}

    }

    return 0;
}



static struct kfs_fops vm_ctrl_fops = {
    //	.open = palacios_open, 
    //	.write = palacios_write,
    //	.read = palacios_read,
    //	.poll = palacios_poll, 
    //	.close = palacios_close,
    .unlocked_ioctl = vm_ioctl,
};

int palacios_create_vm(struct v3_guest * guest)  {
    
    INIT_LIST_HEAD(&(guest->exts));
    
    init_vm_extensions(guest);
    
    guest->v3_ctx = v3_create_vm(guest->img, guest, guest->name);


    {
	char cmd_file[128];

	memset(cmd_file, 0, 128);
	snprintf(cmd_file, 128, "/palacios-vm%d", guest->guest_id);

	kfs_create(cmd_file, NULL, 
		   &vm_ctrl_fops, 
		   0777, guest, sizeof(uintptr_t));

    }


    
    printk("Created VM (id=%d) at %p\n", guest->guest_id, guest);
    

    return 0;
}
