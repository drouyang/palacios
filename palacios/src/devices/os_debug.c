/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */



#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <palacios/vm_guest_mem.h>

#define BUF_SIZE 1024

#define DEBUG_PORT1    0xc0c0
#define HEARTBEAT_PORT 0x0099

struct debug_state {
    char   debug_buf[BUF_SIZE];
    uint32_t debug_offset;

};


static int 
handle_gen_write(struct v3_core_info * core, 
		 uint16_t              port, 
		 void                * src, 
		 uint_t                length, 
		 void                * priv_data)
{
    struct debug_state * state = priv_data;

    state->debug_buf[state->debug_offset++] = *(char*)src;

    if ((*(char *)src == 0xa) || (state->debug_offset == (BUF_SIZE - 1))) {
	PrintDebug("VM_CONSOLE>%s", state->debug_buf);

	memset(state->debug_buf, 0, BUF_SIZE);
	state->debug_offset = 0;
    }

    return length;
}

static int 
handle_hb_write(struct v3_core_info * core, 
		uint16_t              port, 
		void                * src, 
		uint_t                length, 
		void                * priv_data)
{
    uint32_t val = 0;

    if (length == 1) {
	val = *(uint8_t  *)src;
    } else if (length == 2) {
	val = *(uint16_t *)src;
    } else {
	val = *(uint32_t *)src;
    }

    V3_Print("HEARTBEAT> %x (%d)\n", val, val);

    return length;
}

static int 
handle_hcall(struct v3_core_info * core, 
	     uint_t                hcall_id, 
	     void                * priv_data) 
{
    struct debug_state * state = (struct debug_state *)priv_data;

    int    msg_len   = core->vm_regs.rcx;
    addr_t msg_gpa   = core->vm_regs.rbx;
    int    buf_is_va = core->vm_regs.rdx;

    if (msg_len >= BUF_SIZE) {
	PrintError("Console message too large for buffer (len=%d)\n", msg_len);
	return -1;
    }

    if (buf_is_va == 1) {
	if (v3_read_gva(core, msg_gpa, msg_len, (uint8_t *)state->debug_buf) != msg_len) {
	    PrintError("Could not read debug message\n");
	    return -1;
	}
    } else {
	if (v3_read_gpa(core, msg_gpa, msg_len, (uint8_t *)state->debug_buf) != msg_len) {
	    PrintError("Could not read debug message\n");
	    return -1;
	}
    }	

    state->debug_buf[msg_len] = 0;

    PrintDebug("VM_CONSOLE>%s\n", state->debug_buf);

    return 0;
}



static int 
debug_free(struct debug_state * state) 
{

    // unregister hypercall

    V3_Free(state);
    return 0;
};

#ifdef V3_CONFIG_CHECKPOINT

struct dbg_chkpt {
    char     debug_buf[BUF_SIZE];
    uint32_t debug_offset;

} __attribute__((packed));

static int 
debug_save(char               * name, 
	   struct dbg_chkpt   * chkpt, 
	   size_t               size,
	   struct debug_state * dbg) 
{
    memcpy(chkpt->debug_buf, dbg->debug_buf, BUF_SIZE);
    chkpt->debug_offset = dbg->debug_offset;

    return 0;
}


static int 
debug_load(char               * name, 
	   struct dbg_chkpt   * chkpt, 
	   size_t               size,
	   struct debug_state * dbg) 
{
    memcpy(dbg->debug_buf, chkpt->debug_buf, BUF_SIZE);
    dbg->debug_offset = chkpt->debug_offset;

    return 0;
}

#endif



static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))debug_free,
};




static int 
debug_init(struct v3_vm_info * vm, 
	   v3_cfg_tree_t     * cfg) 
{
    struct debug_state * state  = NULL;
    char               * dev_id = v3_cfg_val(cfg, "ID");

    state = (struct debug_state *)V3_Malloc(sizeof(struct debug_state));

    if (!state) {
	PrintError("Cannot allocate in init\n");
	return -1;
    }

    PrintDebug("Creating OS Debug Device\n");

    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, state);

    if (dev == NULL) {
	PrintError("Could not attach device %s\n", dev_id);
	V3_Free(state);
	return -1;
    }

    if (v3_dev_hook_io(dev, DEBUG_PORT1,   NULL, &handle_gen_write) == -1) {
	PrintError("Error hooking OS debug IO port\n");
	v3_remove_device(dev);
	return -1;
    }


    if (v3_dev_hook_io(dev, HEARTBEAT_PORT, NULL, &handle_hb_write) == -1) {
	PrintError("error hooking OS heartbeat port\n");
	v3_remove_device(dev);
	return -1;
    }

    v3_register_hypercall(vm, OS_DEBUG_HCALL, handle_hcall, state);

    state->debug_offset = 0;
    memset(state->debug_buf, 0, BUF_SIZE);
  
#ifdef V3_CONFIG_CHECKPOINT
    v3_checkpoint_register(vm, "OS_DEBUG", 
			   (v3_chkpt_save_fn)debug_save, 
			   (v3_chkpt_load_fn)debug_load,
			   sizeof(struct dbg_chkpt), 
			   state);
#endif


    return 0;
}


device_register("OS_DEBUG", debug_init)
