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
vm_ioctl(struct file   * filp,
	 unsigned int    cmd,
	 unsigned long   arg) 
{
	struct v3_guest * guest = filp->inode->priv;
	//  void __user * argp = (void __user *)arg;

	//printk("VM IOCTL: %d (guest=%p)\n", cmd, guest);

	if (!guest) {
		printk("No Guest registered at %d\n", guest->guest_id);
		return -1;
	}

	switch (cmd) {
	    case V3_VM_LAUNCH: {
		    unsigned int mask = 0;

		    printk("Starting Palacios VM (VM=%d)\n", guest->guest_id);
	
		    mask = (1 << (cpus_weight(cpu_online_map))) - 1;

		    return v3_start_vm(guest->v3_ctx, mask);
		    break;
	    }
	    case V3_VM_STOP: {
		    printk("Stopping VM (%s) (%p)\n", guest->name, guest);

		    if (irqs_disabled()) {
			    printk(KERN_ERR "WHAT!!?? IRQs are disabled??\n");
			    break;
		    }

		    v3_stop_vm(guest->v3_ctx);
		    break;
	    }
	    case V3_VM_PAUSE: {
		    printk("Pausing VM (%s)\n", guest->name);
		    v3_pause_vm(guest->v3_ctx);
		    break;
	    }
	    case V3_VM_CONTINUE: {
		    printk("Continuing VM (%s)\n", guest->name);
		    v3_continue_vm(guest->v3_ctx);
		    break;
	    }
	    case V3_VM_SIMULATE: {
		    printk("Simulating VM (%s) for %lu msecs\n", guest->name, arg);
		    v3_simulate_vm(guest->v3_ctx, arg);
		    break;
	    }
	    case V3_VM_DEBUG: {
		    struct v3_debug_cmd   cmd;
		    struct v3_debug_event evt;
		    void __user * argp = (void __user *)arg;	    

		    memset(&cmd, 0, sizeof(struct v3_debug_cmd));
	    
		    if (copy_from_user(&cmd, argp, sizeof(struct v3_debug_cmd))) {
			    ERROR("Error: Could not copy debug command from user space\n");
			    return -EFAULT;
		    }

		    evt.core_id = cmd.core;
		    evt.cmd     = cmd.cmd;

		    printk("Debugging VM (core %d)\n", cmd.core);

		    if (v3_deliver_debug_event(guest->v3_ctx, &evt) == -1) {
			    ERROR("Error could not deliver debug cmd\n");
			    return -EFAULT;
		    }

		    break;
	    }
	    case V3_VM_MOVE_CORE: {
		    struct v3_core_move_cmd cmd;
		    void __user * argp = (void __user *)arg;

		    memset(&cmd, 0, sizeof(struct v3_core_move_cmd));
	    
		    if (copy_from_user(&cmd, argp, sizeof(struct v3_core_move_cmd))) {
			    ERROR("copy from user error getting migrate command...\n");
			    return -EFAULT;
		    }
	
		    printk("moving guest %s vcore %d to CPU %d\n", 
			   guest->name, cmd.vcore_id, cmd.pcore_id);

		    v3_move_vm_core(guest->v3_ctx, cmd.vcore_id, cmd.pcore_id);

		    break;
	    }
	    default: {
		    return call_guest_ctrl(guest, cmd, arg);
	    }

	}

	return 0;
}



static struct kfs_fops vm_ctrl_fops = {
	//	.open   = palacios_open, 
	//	.write  = palacios_write,
	//	.read   = palacios_read,
 	//	.poll   = palacios_poll, 
	//	.close  = palacios_close,
	.unlocked_ioctl = vm_ioctl,
};

int
palacios_create_vm(struct v3_guest * guest) 
{
    
	INIT_LIST_HEAD(&(guest->exts));
    
	init_vm_extensions(guest);
    
	guest->v3_ctx = v3_create_vm(guest->img, guest, guest->name);

	if (guest->v3_ctx == NULL) {
		ERROR("Error: Could not create VM (%s)\n", guest->name);
		deinit_vm_extensions(guest);
		return -1;
	}


	{
		char cmd_file[128];

		memset(cmd_file, 0, 128);
		snprintf(cmd_file, 128, V3_VM_PATH "%d", guest->guest_id);

		guest->kfs_inode = kfs_create(cmd_file, NULL, 
					      &vm_ctrl_fops, 
					      0777, guest, sizeof(uintptr_t));

		if (guest->kfs_inode == NULL) {
			ERROR("Could not create KFS command file (%s)\n", cmd_file);

			v3_free_vm(guest->v3_ctx);
			deinit_vm_extensions(guest);

			return -1;
		}
		
	}

	v3_lwk_printk("Created VM (id=%d) at %p\n", guest->guest_id, guest);
    

	return 0;
}




int 
palacios_free_vm(struct v3_guest * guest) 
{

	kfs_destroy(guest->kfs_inode);
	
	if (v3_free_vm(guest->v3_ctx) < 0) { 
		return -1;
	}
	
	free_guest_ctrls(guest);
	

	
	return 0;
}
