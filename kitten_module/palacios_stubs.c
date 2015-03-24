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
 * This is free software.  You are permitted to use, redistribute,
 * and modify it under the terms of the GNU General Public License
 * Version 2 (GPLv2).  The accompanying COPYING file contains the
 * full text of the license.
 */

#include <lwk/kernel.h>
#include <lwk/smp.h>
#include <lwk/pmem.h>
#include <lwk/string.h>
#include <lwk/cpuinfo.h>
#include <lwk/driver.h>
#include <lwk/kthread.h>
#include <arch/page.h>
#include <arch/ptrace.h>
#include <arch/apic.h>
#include <arch/idt_vectors.h>
#include <arch/proto.h>
#include "palacios.h"
#include <lwk/signal.h>
#include <lwk/xcall.h>
#include <lwk/interrupt.h>
#include <lwk/sched.h>
#include <lwk/sched_control.h>
#include <lwk/cpuinfo.h>
#include <arch/io.h>
#include <arch/unistd.h>
#include <arch/vsyscall.h>
#include <arch/io_apic.h>
#include <arch/i387.h>


/**
 * Global guest state... only one guest is supported currently.
 */
static struct v3_vm_info * irq_to_guest_map[NUM_IDT_ENTRIES];

/**
 * Sends a keyboard key press event to Palacios for handling.
 */
void
send_key_to_palacios(
		     struct v3_guest * guest, 
		     unsigned char		status,
		     unsigned char		scan_code
)
{
	if (!guest)
		return;

	struct v3_keyboard_event event = {
		.status    = status,
		.scan_code = scan_code,
	};

	v3_deliver_keyboard_event(guest->v3_ctx, &event);
}

/**
 * Sends a timer tick event to Palacios for handling.
 */
void
send_tick_to_palacios(
		      struct v3_guest * guest, 
		      unsigned int		period_us
)
{
	if (!guest)
		return;

	struct v3_timer_event event = {
		.period_us = period_us,
	};

	v3_deliver_timer_event(guest->v3_ctx, &event);
}

/**
 * Prints a message to the console.
 * TODO: Prefix print messages with vm->name and vcore
 */
static void
palacios_print(
	const char *		format,
	...
)
{
	va_list ap;
	va_start(ap, format);
	vprintk(format, ap);
	va_end(ap);
}

/**
 * Allocates a contiguous region of pages of the requested size.
 * Returns the physical address of the first page in the region.
 *
 * TODO: Actually use node_id and constraint arguments
 */
static void *
palacios_allocate_pages(
	int			num_pages,
	unsigned int		alignment,	// must be power of two
	int			node_id
)
{
	struct pmem_region result;
	int status;

	printk("Allocating %d pages (alignment = %x)\n", num_pages, alignment);

	/* Allocate from the user-managed physical memory pool */
	status = pmem_alloc_umem(num_pages * PAGE_SIZE, alignment, &result);
	if (status)
		return NULL;

	/* Zero the memory before handing it to Palacios */
	status = pmem_zero(&result);
	if (status)
		return NULL;

	/* Return the physical address of the region */
	return (void *) result.start;
}

/**
 * Frees pages previously allocated via palacios_allocate_pages().
 */
static void
palacios_free_pages(
        void *			page_paddr,
	int                     num_pages
) 
{
	struct pmem_region	query;
	struct pmem_region	result;
	int 			status;

	pmem_region_unset_all(&query);

	query.start		= (uintptr_t) page_paddr;
	query.end		= (uintptr_t) page_paddr + num_pages * PAGE_SIZE;
	query.allocated		= true;
	query.allocated_is_set	= true;

	status = pmem_query(&query, &result);
	if (status)
		panic("Freeing page %p failed! query status=%d",
		      page_paddr, status);

	result.allocated = false;
	status = pmem_update(&result);
	if (status)
		panic("Failed to free page %p! (status=%d)",
		      page_paddr, status);
}

/**
 * Allocates 'size' bytes of kernel memory.
 * Returns the kernel virtual address of the memory allocated.
 */
static void *
palacios_alloc(
	unsigned int		size
)
{
	return kmem_alloc(size);
}

/**
 * Frees memory that was previously allocated by palacios_alloc().
 */
static void
palacios_free(
	void *			addr
)
{
	return kmem_free(addr);
}

/**
 * Converts a kernel virtual address to the corresponding physical address.
 */
static void *
palacios_vaddr_to_paddr(
	void *			vaddr
)
{
	return (void *) __pa(vaddr);
}

/**
 * Converts a physical address to the corresponding kernel virtual address.
 */
static void *
palacios_paddr_to_vaddr(
	void *			paddr
)
{
	return (void *) __va(paddr);
}

/**
 * Runs a function on the specified CPU.
 */
static void 
palacios_xcall(
	int			cpu_id, 
	void			(*fn)(void *arg),
	void *			arg
)
{
	cpumask_t cpu_mask;

	cpus_clear(cpu_mask);
	cpu_set(cpu_id, cpu_mask);

	printk(KERN_WARNING
		"Palacios making xcall to cpu %d from cpu %d.\n",
		cpu_id, current->cpu_id);

	xcall_function(cpu_mask, fn, arg, 1);
}


/**
 * Returns the CPU ID that the caller is running on.
 */
static unsigned int 
palacios_get_cpu(void) 
{
	return this_cpu;
}

/**
 * Interrupts the physical CPU corresponding to the specified logical guest cpu.
 * If (vector == 0) then it is just an interrupt with no effect, this merely kicks the 
 * core out of the guest context
 *
 * NOTE: 
 * This is dependent on the implementation of xcall_reschedule().  Currently
 * xcall_reschedule does not explicitly call schedule() on the destination CPU,
 * but instead relies on the return to user space to handle it. Because
 * palacios is a kernel thread schedule will not be called, which is correct.
 * We should have a default palacios IRQ that just handles the IPI and returns immediately
 * with no side effects.
 */
static void
palacios_interrupt_cpu(
	struct v3_vm_info*	vm, 
	int			cpu_id,
	int                     vector
)
{

	if (cpu_id != current->cpu_id) {
		if (vector == 0) 
			xcall_reschedule(cpu_id);
		else 
			lapic_send_ipi(cpu_id, vector);
	}
}

  
/**
 * Returns the CPU frequency in kilohertz.
 */
static unsigned int
palacios_get_cpu_khz(void) 
{
	return cpu_info[0].arch.cur_cpu_khz;
}

/**
 * Yield the CPU so other host OS tasks can run.
 */
static void
palacios_yield_cpu(void)
{
	schedule();
}


/** 
 * Yields to another thread specified via the pid/tid pair 
 */
static void
palacios_yield_to_pid(unsigned int pid,
		      unsigned int tid)
{
    sched_yield_task_to(pid, tid);
}


/**
 * Puts the caller to sleep 'usec' microseconds.
 */
static void
palacios_sleep_cpu(
	unsigned int		usec
)
{
	schedule_timeout(usec * 1000);
}

/**
 * Creates a kernel thread.
 */
static void *
palacios_create_thread(
	int (*fn)		(void *arg),
	void *			arg,
	char *			thread_name
)
{
    return kthread_create(fn, arg, thread_name);
}

/**
 * Starts a kernel thread on the specified CPU.
 */
static void *
palacios_create_thread_on_cpu(
	int			cpu_id, 
	int			(*fn)(void * arg), 
	void *			arg, 
	char *			thread_name
)
{
    return kthread_create_on_cpu(cpu_id, fn, arg, thread_name);
}

/**
 * Starts a kernel thread
 */
static void
palacios_start_thread(
	void * thread
)
{
    struct task_struct * task = (struct task_struct *)thread;

    sched_wakeup_task(task, TASK_ALL);
}



/**
 * Save the host's FPU state
 */
void palacios_save_fpu(void) {
    kernel_fpu_begin();
}


/**
 * Restore the host's FPU state
 */
void palacios_restore_fpu(void) {
    kernel_fpu_end();
}

/**
 * Allocates a mutex.
 * Returns NULL on failure.
 */
static void *
palacios_mutex_alloc(void)
{
    struct semaphore * sem = kmem_alloc(sizeof(struct semaphore));
    if (sem) {
        sema_init(sem, 1);
    } else {
        printk(KERN_ERR "unable to allocate semaphore\n");
        return NULL;
    }

    return sem;
}

/**
 * Frees a mutex.
 */
static void
palacios_mutex_free(void * mutex)
{
	kmem_free(mutex);
}

/**
 * Locks a mutex.
 */
static void 
palacios_mutex_lock(void * mutex)
{
    down(mutex);
}

/**
 * Unlocks a mutex.
 */
static void 
palacios_mutex_unlock(void * mutex)
{
    up(mutex);
}


/**
 * Structure used by the Palacios hypervisor to interface with the host kernel.
 */
static struct v3_os_hooks palacios_os_hooks = {
	.print			= palacios_print,
	.allocate_pages		= palacios_allocate_pages,
	.free_pages		= palacios_free_pages,
	.malloc			= palacios_alloc,
	.free			= palacios_free,
	.vaddr_to_paddr		= palacios_vaddr_to_paddr,
	.paddr_to_vaddr		= palacios_paddr_to_vaddr,
	.get_cpu_khz		= palacios_get_cpu_khz,
	.yield_cpu		= palacios_yield_cpu,
	.yield_to_pid           = palacios_yield_to_pid,
	.yield_to_thread        = NULL,
	.sleep_cpu		= palacios_sleep_cpu,
	.save_fpu               = palacios_save_fpu,
	.restore_fpu            = palacios_restore_fpu,
	.mutex_alloc		= palacios_mutex_alloc,
	.mutex_free		= palacios_mutex_free,
	.mutex_lock		= palacios_mutex_lock, 
	.mutex_unlock		= palacios_mutex_unlock,
	.get_cpu		= palacios_get_cpu,
	.interrupt_cpu		= palacios_interrupt_cpu,
	.call_on_cpu		= palacios_xcall,
	.create_thread		= palacios_create_thread,
	.create_thread_on_cpu	= palacios_create_thread_on_cpu,
	.start_thread		= palacios_start_thread,
};


int palacios_vmm_init(char * options) 
{
    Init_V3(&palacios_os_hooks, NULL, cpus_weight(cpu_online_map), options);
    return 0;
}



#if 0
/**
 * Direct keyboard interrupts to the Palacios hypervisor.
 */
static irqreturn_t
palacios_keyboard_interrupt(
	int			vector,
	void *			unused
)
{
	const uint8_t KB_STATUS_PORT = 0x64;
	const uint8_t KB_DATA_PORT   = 0x60;
	const uint8_t KB_OUTPUT_FULL = 0x01;

	uint8_t status = inb(KB_STATUS_PORT);

	if ((status & KB_OUTPUT_FULL) == 0)
		return IRQ_NONE;

	uint8_t key = inb(KB_DATA_PORT);
	send_key_to_palacios(NULL, status, key);

	return IRQ_HANDLED;
}
#endif
