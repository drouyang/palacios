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

#include <palacios/vmm_excp.h>
#include <palacios/vmm.h>
#include <palacios/vmm_types.h>
#include <palacios/vm.h>
#include <palacios/vmm_sprintf.h>




#ifdef V3_CONFIG_CHECKPOINT

struct excp_chkpt {
    uint32_t excp_bitmap;
    uint32_t error_bitmap;
    uint32_t error_codes[32];
} __attribute__((packed));


static int 
excp_save(char                * name, 
	  struct excp_chkpt   * chkpt, 
	  size_t                size,
	  struct v3_core_info * core)
{
    struct v3_excp_state * excp_state = &(core->excp_state);

    chkpt->excp_bitmap  = excp_state->excp_bitmap;
    chkpt->error_bitmap = excp_state->error_bitmap;
    memcpy(chkpt->error_codes, excp_state->error_codes, sizeof(chkpt->error_codes));

    V3_Print("Checkpointing EXCP state: error_codes size = %lu. (should be 128)\n", sizeof(chkpt->error_codes));

    return 0;
}


static int 
excp_load(char                * name, 
	  struct excp_chkpt   * chkpt, 
	  size_t                size,
	  struct v3_core_info * core)
{
    struct v3_excp_state * excp_state = &(core->excp_state);

    excp_state->excp_bitmap  = chkpt->excp_bitmap;
    excp_state->error_bitmap = chkpt->error_bitmap;
    memcpy(excp_state->error_codes, chkpt->error_codes, sizeof(chkpt->error_codes));

    return 0;
}

#endif

void 
v3_init_exception_state(struct v3_core_info * core) 
{
    int i = 0;

    core->excp_state.excp_bitmap    = 0;
    core->excp_state.error_bitmap   = 0;

    for (i = 0; i < 32; i++) {
	core->excp_state.error_codes[i] = 0;
    }

    v3_spinlock_init(&(core->excp_state.excp_lock));

#ifdef V3_CONFIG_CHECKPOINT
    {
	char tag[32] = {[0 ... 31] = 0};

	snprintf(tag, 31, "core-%u-EXCP", core->vcpu_id);
	
	v3_checkpoint_register(core->vm_info, tag,
			       (v3_chkpt_save_fn)excp_save, 
			       (v3_chkpt_load_fn)excp_load, 
			       sizeof(struct excp_chkpt), 
			       core);
    }
#endif


}





int 
v3_raise_exception_with_error(struct v3_core_info * core, 
			      uint32_t              excp, 
			      uint32_t              error_code) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    uint64_t flags;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {

	if ((excp_state->excp_bitmap & (1 << excp)) == 0) {
	    
	    excp_state->excp_bitmap        |= (1 << excp);
	    excp_state->error_bitmap       |= (1 << excp);
	    excp_state->error_codes[excp]   = error_code;
	    
	    //	PrintDebug("[v3_raise_exception_with_error] error code: %x\n", error_code);
	} else {
	    PrintError("Error injecting exception_w_error (excp=%d) (error=%d): Already pending\n",
		       excp, error_code);
	    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);
	    return -1;
	}
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return 0;
}

int 
v3_raise_exception(struct v3_core_info * core, 
		   uint32_t              excp) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    uint64_t flags;
    //PrintDebug("[v3_raise_exception]\n");

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {

	if ((excp_state->excp_bitmap & (1 << excp)) ==  0) {
	    
	    excp_state->excp_bitmap |= (1 << excp);
	    
	} else {
	    PrintError("Error injecting exception (excp=%d): Already pending\n",
		       excp);
	    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);
	    return -1;
	}
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return 0;
}


int 
v3_raise_nmi(struct v3_core_info * core)
{
    return v3_raise_exception(core, NMI_EXCEPTION);
}


int 
v3_excp_pending(struct v3_core_info * core) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    int    ret = 0;
    addr_t flags;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {
	if (excp_state->excp_bitmap != 0) {
	   ret = 1;
	}
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return ret;
}


uint32_t
v3_get_excp_number(struct v3_core_info * core) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    uint32_t vec   = -1;
    addr_t   flags = 0;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {

	__asm__ __volatile__ ("bsfl %1, %0\n"
			      "jnz 1f\n"
			      "movl $-1, %0\n"
			      "1:" 
			      : "=r"(vec)
			      : "rm"(excp_state->excp_bitmap)
			      :);

    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return vec;
}


int 
v3_excp_has_error(struct v3_core_info * core, 
		  uint32_t              excp) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    int    ret = 0;
    addr_t flags;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {
	if (( excp_state->error_bitmap & (1 << excp)) != 0) {
	    ret = 1;
	}
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return ret;
}

uint32_t
v3_get_excp_error(struct v3_core_info * core, 
		  uint32_t              excp) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    uint32_t err_code = 0;
    addr_t flags;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {
	err_code = excp_state->error_codes[excp];
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return err_code;
}

int 
v3_injecting_excp(struct v3_core_info * core, 
		  uint32_t              excp) 
{
    struct v3_excp_state * excp_state = &(core->excp_state);
    addr_t flags;

    flags = v3_spin_lock_irqsave(&(excp_state->excp_lock));
    {
	excp_state->excp_bitmap  &= ~(1 << excp);
	excp_state->error_bitmap &= ~(1 << excp);
	
    }
    v3_spin_unlock_irqrestore(&(excp_state->excp_lock), flags);

    return 0;
}
