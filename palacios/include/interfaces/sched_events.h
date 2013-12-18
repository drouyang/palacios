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

#ifndef __SCHED_EVENTS_H__
#define __SCHED_EVENTS_H__

#ifdef __V3VEE__

int v3_hook_core_preemptions(struct guest_info * core, 
			     int (*sched_in)(struct guest_info * core, int cpu), 
			     int (*sched_out)(struct guest_info * core, int cpu));

int v3_unhook_core_preemptions(struct guest_info * core, 
			       int (*sched_in)(struct guest_info * core, int cpu), 
			       int (*sched_out)(struct guest_info * core, int cpu));


#endif


struct v3_sched_hooks {
    int (*hook_sched_evts)(int (*sched_in)(void * arg, int cpu),
			   int (*sched_out)(void * arg, int cpu),
			   void * arg);
    int (*unhook_sched_evts)(int (*sched_in)(void * arg, int cpu), 
			     int (*sched_out)(void * arg, int cpu), 
			     void * arg);
};

extern void V3_Init_SchedEvents(struct v3_sched_hooks * hooks);

#endif
