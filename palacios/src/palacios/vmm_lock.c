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

#define v3_irqsave(x) do { __asm__ __volatile__("# local_irq_save \n\t pushfq ; popq %0 ; cli":"=g" (x): /* no input */ :"memory"); } while (0)
#define v3_irqrestore(x) __asm__ __volatile__("# restore_flags \n\t pushq %0 ; popfq": /* no output */ :"g" (x):"memory", "cc")


extern struct v3_os_hooks * os_hooks;

static inline void v3_cpu_relax(void) {
  __asm__ __volatile__("rep;nop": : :"memory");
}

static inline unsigned long v3_xchg8(volatile void * ptr, unsigned char x ) {
  __asm__ __volatile__("xchgb %0,%1"
      :"=r" (x)
      :"m" (*(volatile unsigned char *)ptr), "0" (x)
      :"memory");
  return x;
}

int v3_spinlock_init(v3_spinlock_t * lock)
{

    *lock = (addr_t) V3_Malloc(sizeof(unsigned char));

    if (!(*lock)) {
        return -1;
    }

    *(unsigned char *) *lock = 0;

    return 0;

}

void v3_spinlock_deinit(v3_spinlock_t * lock)
{
    V3_Free((void *)*lock);
    *lock = 0;
}


void v3_spin_lock(v3_spinlock_t lock)
{
  while (1) {
    if (v3_xchg8((void *)lock, 1) == 0) {
      return;
    }
    v3_cpu_relax();
  }
}


void v3_spin_unlock(v3_spinlock_t lock)
{
  __asm__ __volatile__ ("": : :"memory");
  *(unsigned char *)lock = 0;
}

addr_t v3_spin_lock_irqsave(v3_spinlock_t lock)
{
    unsigned long flags;

    v3_irqsave(flags);
    v3_spin_lock(lock);

    return (addr_t) flags;
}

void v3_spin_unlock_irqrestore(v3_spinlock_t lock, addr_t flags)
{
    v3_spin_unlock(lock);
    v3_irqrestore(flags);
}

int v3_mutex_init(v3_mutex_t * mutex) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_alloc);

    *mutex = (addr_t)(os_hooks->mutex_alloc());

    if (!(*mutex)) {
        return -1;
    }

    return 0;
}


void v3_mutex_deinit(v3_mutex_t * mutex) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_free);

    os_hooks->mutex_free((void *)*mutex);
    *mutex = 0;
}

void v3_mutex_lock(v3_mutex_t mutex) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_lock);

    os_hooks->mutex_lock((void *)mutex);
}

void v3_mutex_unlock(v3_mutex_t mutex) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->mutex_unlock);

    os_hooks->mutex_unlock((void *)mutex);
}

