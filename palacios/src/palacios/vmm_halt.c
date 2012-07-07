/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Peter Dinda <pdinda@northwestern.edu>
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Peter Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm_halt.h>
#include <palacios/vmm_intr.h>
#include <palacios/vmm_lowlevel.h> 

#ifndef V3_CONFIG_DEBUG_HALT
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif


#define YIELD_TIME_USEC 1000


//
// This should trigger a #GP if cpl != 0, otherwise, yield to host
//

int v3_handle_halt(struct guest_info * info) {

    if (info->cpl != 0) { 
	v3_raise_exception(info, GPF_EXCEPTION);
    } else {
	PrintDebug("CPU Yield\n");

	while (!v3_intr_pending(info) && (info->vm_info->run_state == VM_RUNNING)) {
            uint64_t t, cycles;
	    /* Yield, allowing time to pass while yielded */
	    t = v3_get_host_time(&info->time_state);
	    v3_yield(info,YIELD_TIME_USEC);
	    cycles = v3_get_host_time(&info->time_state) - t;
	    v3_advance_time(info, &cycles);

	    v3_update_timers(info);
    	    
	    /* At this point, we either have some combination of 
	       interrupts, including perhaps a timer interrupt, or 
	       no interrupt.
	    */
	    if (!v3_intr_pending(info)) {
		/* if no interrupt, then we do halt */
		/* asm("hlt"); */
	    }

	}

	/* V3_Print("palacios: done with halt\n"); */
	
	info->rip += 1;
    }

    return 0;
}
