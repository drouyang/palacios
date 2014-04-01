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

int v3_handle_halt(struct v3_core_info * core) {

    if (core->cpl != 0) { 
	v3_raise_exception(core, GPF_EXCEPTION);
    } else {
	PrintDebug("CPU Yield\n");

	while (!v3_intr_pending(core) && (core->vm_info->run_state == VM_RUNNING)) {
            uint64_t t, cycles;
	    /* Yield, allowing time to pass while yielded */
	    t = v3_get_host_time(&core->time_state);
	    v3_yield(core,YIELD_TIME_USEC);
	    cycles = v3_get_host_time(&core->time_state) - t;
	    v3_advance_time(core, &cycles);

	    v3_update_timers(core);
    	    
	    /* At this point, we either have some combination of 
	       interrupts, including perhaps a timer interrupt, or 
	       no interrupt.
	    */
	    if (!v3_intr_pending(core)) {
		/* if no interrupt, then we do halt */
		/* asm("hlt"); */
	    }

	    // This is needed to ensure that an idled CPU can be reawoken via IPI
	    v3_wait_at_barrier(core);

	    if (core->core_run_state == CORE_STOPPED) {
		// We have been initted and reset, bail out to catch the restart
		break;
	    }

	}

	/* V3_Print("palacios: done with halt\n"); */
	
	core->rip += 1;
    }

    return 0;
}
