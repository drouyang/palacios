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
#include <palacios/vmm_lock.h>
#include <palacios/vmm_lowlevel.h>


extern struct v3_os_hooks * os_hooks;


int v3_lock_init(v3_lock_t * lock) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_alloc);

    *lock = (addr_t)(os_hooks->mutex_alloc());

    if (!(*lock)) {
	return -1;
    }

    return 0;
}


void v3_lock_deinit(v3_lock_t * lock) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_free);

    os_hooks->mutex_free((void *)*lock);
    *lock = 0;
}

void v3_lock(v3_lock_t lock) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_lock);

    os_hooks->mutex_lock((void *)lock, 0);    
}

void v3_unlock(v3_lock_t lock) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_unlock);

    os_hooks->mutex_unlock((void *)lock);
}

addr_t v3_lock_irqsave(v3_lock_t lock) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_lock_irqsave);

    return (addr_t) (os_hooks->mutex_lock_irqsave((void *)lock, 1));
}


void v3_unlock_irqrestore(v3_lock_t lock, addr_t irq_state) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_unlock_irqrestore);

    os_hooks->mutex_unlock_irqrestore((void *)lock,(void*)irq_state);
}
