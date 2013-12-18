/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2013, Jack Lange (jacklange@cs.pitt.edu> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmm.h>
#include <palacios/vmm_debug.h>
#include <palacios/vmm_types.h>
#include <palacios/vm_guest.h>

#include <interfaces/sched_events.h>

static struct v3_sched_hooks * sched_hooks = NULL;


void V3_Init_SchedEvents(struct v3_sched_hooks * hooks) {
    sched_hooks = hooks;
    V3_Print("V3 Host Scheduler event interface initialized\n");
    return;
}

int v3_hook_core_preemptions(struct guest_info * core, 
			     int (*sched_in)(struct guest_info * core, int cpu), 
			     int (*sched_out)(struct guest_info * core, int cpu)) {
    if ((sched_hooks == NULL) || 
	(sched_hooks->hook_sched_evts == NULL)) {
	PrintError("Error: Scheduler event hooks not initialized correctly\n");
	PrintError("sched_hooks = %p, sched_hooks->hook_sched_evts = %p\n",
		   sched_hooks, sched_hooks->hook_sched_evts);

	return -1;
    }

    sched_hooks->hook_sched_evts((int (*)(void * arg, int cpu))sched_in, 
				 (int (*)(void * arg, int cpu))sched_out, 
				 (void *)core);

    return 0;
}



int v3_unhook_core_preemptions(struct guest_info * core, 
			       int (*sched_in)(struct guest_info * core, int cpu), 
			       int (*sched_out)(struct guest_info * core, int cpu)) {
    if ((sched_hooks == NULL) || 
	(sched_hooks->unhook_sched_evts == NULL)) {
	PrintError("Error: Scheduler event hooks not initialized correctly\n");
	PrintError("sched_hooks = %p, sched_hooks->unhook_sched_evts = %p\n",
		   sched_hooks, sched_hooks->unhook_sched_evts);

	return -1;
    }

    sched_hooks->unhook_sched_evts((int (*)(void * arg, int cpu))sched_in, 
				   (int (*)(void * arg, int cpu))sched_out, 
				   (void *)core);


    return 0;
}
