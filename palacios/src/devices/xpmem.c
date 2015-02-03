/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2014, Brian Kocoloski <briankoco@cs.pitt.edu> 
 * Copyright (c) 2014, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/svm.h>
#include <palacios/vmx.h>
#include <palacios/vmm_list.h>
#include <palacios/vmm_lock.h>
#include <palacios/vm_guest_mem.h>
#include <interfaces/vmm_xpmem.h>
#include <devices/pci.h>
#include <devices/pci_types.h>
#include <devices/xpmem.h>


#ifndef V3_CONFIG_DEBUG_XPMEM
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEV_ID        0x100d
#define XPMEM_SUBDEVICE_ID  13



struct xpmem_bar_state {
    /* Hypercall numbers */
    uint32_t xpmem_hcall_id;
    uint32_t xpmem_detach_hcall_id;
    uint32_t xpmem_irq_clear_hcall_id;
    uint32_t xpmem_read_cmd_hcall_id;

    /* VMX-enabled */
    uint8_t vmx_capable;

    /* SVM-enabled */
    uint8_t svm_capable;
 
    /* interrupt status */
    uint8_t irq_handled;

    /* size of xpmem cmd size */
    uint64_t xpmem_cmd_size;

    /* size of requested buffer for attachment operations */
    uint64_t xpmem_pfn_size;
};
 
struct xpmem_memory_map {
    struct list_head free_list;
    struct list_head alloc_list;
};

struct xpmem_memory_region {
    addr_t           guest_start;
    addr_t           guest_end;
    struct list_head node;
};

struct v3_xpmem_state {
    struct v3_vm_info   * vm;
    struct vm_device    * pci_bus;
    struct pci_device   * pci_dev;

    /* state lock */
    v3_spinlock_t            lock;

    /* handle to host state */
    xpmem_host_handle_t      host_handle;

    /* bar exposed to guest */
    struct xpmem_bar_state * bar_state;

    /* list of XPMEM commands to be delivered to the guest */
    struct list_head         cmd_list;

    /* hashtables of host <-> guest page list physical addresses */
    struct hashtable       * htg_table;
    struct hashtable       * gth_table;

    /* guest XPMEM memory map */
    struct xpmem_memory_map  mem_map;
};

struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    struct list_head      node;
};


static uint32_t 
xpmem_paddr_to_pfn(addr_t paddr)
{
    return paddr >> PAGE_POWER;
}

static addr_t
xpmem_pfn_to_paddr(uint32_t pfn)
{
    return (addr_t)pfn << PAGE_POWER;
}


/*
 * Free list insertion. We insert the region [addr, addr + len) into list,
 * merging with other entries in the list when possible 
 */
static int
__xpmem_insert_free_memory_region(struct xpmem_memory_map  * mem_map,
	  	                  addr_t                     addr,
			          uint64_t                   len)
{
    struct xpmem_memory_region * iter      = NULL;
    struct xpmem_memory_region * prev_iter = NULL;
    struct xpmem_memory_region * next      = NULL;
    struct xpmem_memory_region * new_reg   = NULL;

    struct list_head           * list      = &(mem_map->free_list);

    addr_t start = addr;
    addr_t end   = (addr_t)(addr + len);

    if (list_empty(list)) {
	new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
	if (!new_reg) {
	    PrintError("XPMEM: out of memory\n");
	    return -1;
	}

	new_reg->guest_start = start;
	new_reg->guest_end   = end;

	list_add(&(new_reg->node), list);
	return 0;
    }

    /* Find the right location to insert or merge */
    list_for_each_entry_safe(iter, next, list, node) {

	/* Could be first */
	if (end < iter->guest_start) {

	    /* Check for invalid overlap */
	    if ((prev_iter) && (start < prev_iter->guest_end)) {
		return -1;
	    }

	    /* OK, it's a match */
	    if ((prev_iter) && (prev_iter->guest_end == start)) {
		/* Merge */
		prev_iter->guest_end = end;
	    } else {
		/* No merge possible */
		new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
		if (!new_reg) {
		    PrintError("XPMEM: out of memory\n");
		    return -1;
		}

		new_reg->guest_start = addr;
		new_reg->guest_end   = end;

		list_add_tail(&(new_reg->node), &(iter->node));
	    }

	    return 0;

	} else if (end == iter->guest_start) {
	
	    /* Check for invalid overlap */
	    if ((prev_iter) && (start < prev_iter->guest_end)) {
		return -1;
	    }

	    /* OK, it's a match, and we can merge at the end */
	    iter->guest_start = start;

	    if ((prev_iter) && (prev_iter->guest_end == start)) {
		/* Perfect match, we merge with this and previous - free previous */
		iter->guest_start = prev_iter->guest_start;
		list_del(&(prev_iter->node));
		V3_Free(prev_iter);
	    }

	    /* No merge at the front, but we already merges the back so it's all good */
	    return 0;
	
	}

	prev_iter = iter;
    }

    /* Must be after the last region */

    /* Invalid overlap */
    if (start < prev_iter->guest_end) {
	return -1;
    }

    /* Ok, it's at the end */
    if (start == prev_iter->guest_end) {
	/* Merge */
	prev_iter->guest_end = end;
    } else {
	/* No merge possible */
	new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
	if (!new_reg) {
	    PrintError("XPMEM: out of memory\n");
	    return -1;
	}

	new_reg->guest_start = addr;
	new_reg->guest_end   = end;

	list_add(&(new_reg->node), &(prev_iter->node));
    }

    return 0;
}

static int
xpmem_insert_free_memory_region(struct v3_xpmem_state * state,
		                addr_t                  addr,
			        uint64_t                len)

{
    int ret = 0;

    v3_spin_lock(&(state->lock));
    {
	ret = __xpmem_insert_free_memory_region(
		&(state->mem_map),
		addr,
		len
	);
    }
    v3_spin_unlock(&(state->lock));

    return ret;
}

/*
 * Allocated list insertion. We insert the region [addr, addr + len) into list,
 * but we don't merge entries here
 */
static int
__xpmem_insert_allocated_memory_region(struct xpmem_memory_map  * mem_map,
		                       addr_t                     addr,
			               uint64_t                   len)
{
    struct xpmem_memory_region * iter      = NULL;
    struct xpmem_memory_region * prev_iter = NULL;
    struct xpmem_memory_region * new_reg   = NULL;

    struct list_head           * list = &(mem_map->alloc_list);

    addr_t start = addr;
    addr_t end   = (addr_t)(addr + len);

    if (list_empty(list)) {
	new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
	if (!new_reg) {
	    PrintError("XPMEM: out of memory\n");
	    return -1;
	}

	new_reg->guest_start = start;
	new_reg->guest_end   = end;

	list_add(&(new_reg->node), list);
	return 0;
    }

    /* Find the right location to insert */
    list_for_each_entry(iter, list, node) {

	/* Could be first */
	if (end <= iter->guest_start) {

	    /* Check for invalid overlap */
	    if ((prev_iter) && (start < prev_iter->guest_end)) {
		return -1;
	    }

	    /* OK, it's a match */
	    new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
	    if (!new_reg) {
		PrintError("XPMEM: out of memory\n");
		return -1;
	    }

	    new_reg->guest_start = start;
	    new_reg->guest_end   = end;

	    list_add_tail(&(new_reg->node), &(iter->node));

	    return 0;
	} 

	prev_iter = iter;
    }

    /* Must be after the last region */

    /* Invalid overlap */
    if (start < prev_iter->guest_end) {
	return -1;
    }

    /* OK, it's at the end */
    new_reg = V3_Malloc(sizeof(struct xpmem_memory_region));
    if (!new_reg) {
	PrintError("XPMEM: out of memory\n");
	return -1;
    }

    new_reg->guest_start = start;
    new_reg->guest_end   = end;

    list_add_tail(&(new_reg->node), &(prev_iter->node));

    return 0;
}

static int
xpmem_insert_allocated_memory_region(struct v3_xpmem_state * state,
		                     addr_t                  addr,
			             uint64_t                len)
{
    int ret = 0;

    v3_spin_lock(&(state->lock));
    {
	ret = __xpmem_insert_allocated_memory_region(
		&(state->mem_map),
		addr,
		len
	);
    }
    v3_spin_unlock(&(state->lock));

    return ret;
}

// 32 GB: Start of XPMEM range
#define XPMEM_MEM_START (1ULL << 35)

// 32 GB of addressable XPMEM
#define XPMEM_MEM_END   (1ULL << 36)


/* Find region of len bytes */
static int
__xpmem_find_free_space(struct xpmem_memory_map * mem_map,
                        uint64_t                  len,
                        addr_t                  * addr)
{
    struct xpmem_memory_region * iter = NULL;
    struct xpmem_memory_region * next = NULL;

    struct list_head           * list = &(mem_map->free_list);

    list_for_each_entry_safe(iter, next, list, node) {
	addr_t region_len = iter->guest_end - iter->guest_start;

	if (region_len > (addr_t)len) {
	    /* Shrink a free region */
	    *addr              = iter->guest_start;

	    iter->guest_start += len;
	    return 0;
	} else if (region_len == (addr_t)len) {
	    /* Delete the free region */
	    *addr = iter->guest_start;

	    list_del(&(iter->node));
	    return 0;
	} 
    }

    /* Couldn't find a large enough region */
    return -1;
}

static int
xpmem_find_free_space(struct v3_xpmem_state * state,
		      uint64_t                len,
		      addr_t                * addr)
{
    int ret = 0;

    v3_spin_lock(&(state->lock));
    {
	ret = __xpmem_find_free_space(
		&(state->mem_map),
		len,
		addr
	);
    }
    v3_spin_unlock(&(state->lock));

    return ret;
}

static int
__xpmem_find_and_remove_allocated_region(struct xpmem_memory_map    * mem_map,
                                         addr_t                       addr,
		                         struct xpmem_memory_region * region)
{
    struct xpmem_memory_region * iter = NULL;
    struct xpmem_memory_region * next = NULL;

    struct list_head           * list = &(mem_map->alloc_list);

    list_for_each_entry_safe(iter, next, list, node) {
	if (iter->guest_start == addr) {
	    *region = *iter;
	    list_del(&(iter->node));
	    V3_Free(iter);
	    return 0;
	}
    }

    return -1;
}

static int
xpmem_find_and_remove_allocated_region(struct v3_xpmem_state      * state,
		                       addr_t                       addr,
				       struct xpmem_memory_region * region)
{
    int ret = 0;

    v3_spin_lock(&(state->lock));
    {
	ret = __xpmem_find_and_remove_allocated_region(
		&(state->mem_map),
		addr,
		region
	);
    }
    v3_spin_unlock(&(state->lock));

    return ret;
}


/*
 * Initialize guest memory map
 */
static int
init_xpmem_mem_map(struct v3_xpmem_state * state)
{
    struct xpmem_memory_map * mem_map = &(state->mem_map);

    memset(mem_map, 0, sizeof(struct xpmem_memory_map));

    INIT_LIST_HEAD(&(mem_map->free_list));
    INIT_LIST_HEAD(&(mem_map->alloc_list));

    /* All is free to start */
    return xpmem_insert_free_memory_region(
	state,
	XPMEM_MEM_START, 
	XPMEM_MEM_END - XPMEM_MEM_START
    );
}


/*
 * Map host pfns stored in pfn_list to guest memory
 */
static int
xpmem_add_shadow_region(struct v3_xpmem_state * state,
			uint64_t                num_pfns,
                        uint32_t              * pfn_list)
{
    int    status     = 0;
    addr_t region_len = 0;
    addr_t start_addr = 0;

    region_len = (addr_t)(num_pfns * PAGE_SIZE);

    /* Search for free space */
    status = xpmem_find_free_space(
        state, 
	region_len, 
	&start_addr
    );

    if (status != 0) {
	PrintError("XPMEM: cannot find free region of %llu bytes: "
		"cannot map host memory\n", (unsigned long long)region_len);
	return -1;
    }

    /* Map region into guest. The host range may be discontiguous, so we have to
     * do this a page at a time
     */

//    v3_raise_barrier(state->vm, NULL);
    {
	int i = 0;

	for (i = 0; i < num_pfns; i++) {
	    addr_t guest_pfn  = 0;
	    addr_t guest_paddr = start_addr + (i * PAGE_SIZE);
	    addr_t host_paddr  = xpmem_pfn_to_paddr(pfn_list[i]);

	    status = v3_add_shadow_mem(state->vm,
		V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
		guest_paddr,
		guest_paddr + PAGE_SIZE,
		host_paddr
	    );

	    if (status != 0) {
		PrintError("XPMEM: could not add shadow memory region!\n");
		
		/* Undo whatever mappings were done */
		for (i--; i >= 0; i--) {
		    struct v3_mem_region * old_reg = NULL;

		    guest_paddr = start_addr + (i * PAGE_SIZE);
		    old_reg     = v3_get_mem_region(state->vm, V3_MEM_CORE_ANY, guest_paddr);

		    v3_delete_mem_region(state->vm, old_reg);
		}

		xpmem_insert_free_memory_region(
		    state,
		    start_addr, 
		    region_len
		);

//		v3_lower_barrier(state->vm);
		return -1;
	    }

	    guest_pfn = xpmem_paddr_to_pfn(guest_paddr);

	    PrintDebug("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
		(unsigned long long)guest_pfn,
		(unsigned long long)pfn_list[i],
		(void *)guest_paddr,
		(void *)host_paddr
	    );

	    /* Update pfn list with guest address */
	    pfn_list[i] = (uint32_t)guest_pfn;
	}

	/* OK, the shadow mapping is done - update the alloc list */
	status = xpmem_insert_allocated_memory_region(
	    state, 
	    start_addr, 
	    region_len
	);

	if (status != 0) {
	    PrintError("XPMEM: cannot add region [%p, %p) to guest alloc list\n",
		    (void *)start_addr, (void *)(start_addr + region_len));
//	    v3_lower_barrier(state->vm);
	    return -1;
	}
    }
//    v3_lower_barrier(state->vm);

    return 0;
}


static int 
xpmem_remove_shadow_region(struct v3_xpmem_state * state, 
			   addr_t		   addr, 
			   uint64_t		   len)
{
    uint64_t num_pfns = len / PAGE_SIZE;
    uint64_t i        = 0;

    for (i = 0; i < num_pfns; i++) {
	struct v3_mem_region * old_reg    = NULL;
	addr_t                 guest_addr = addr + (i * PAGE_SIZE);

	guest_addr = addr + (i * PAGE_SIZE);
	old_reg    = v3_get_mem_region(state->vm, V3_MEM_CORE_ANY, guest_addr);

	if (!old_reg) {
	    return -1;
	}

	v3_delete_mem_region(state->vm, old_reg);
    }

    return 0;
}



static int xpmem_free(void * private_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)private_data;

    /* First, disconnect from host */
    v3_xpmem_host_disconnect(state->host_handle);

    /* Free cmd list */
    {
	struct xpmem_cmd_ex_iter * iter = NULL;
	struct xpmem_cmd_ex_iter * next = NULL;

	list_for_each_entry_safe(iter, next, &(state->cmd_list), node) {
	    list_del(&(iter->node));
	    V3_Free(iter->cmd);
	    V3_Free(iter);
	}
    }

    /* Free memory map lists */
    {
	struct xpmem_memory_region * iter = NULL;
	struct xpmem_memory_region * next = NULL;

	/* Free free list */
	list_for_each_entry_safe(iter, next, &(state->mem_map.free_list), node) {
	    list_del(&(iter->node));
	    V3_Free(iter);
	}

	/* Free alloc list */
	list_for_each_entry_safe(iter, next, &(state->mem_map.alloc_list), node) {
	    list_del(&(iter->node));

	    /* We also need to remove these things from the shadow map */
	    xpmem_remove_shadow_region(state, 
		iter->guest_start,
		iter->guest_end - iter->guest_start);

	    V3_Free(iter);
	}
    }

    /* Free bar page */
    V3_FreePages(V3_PAddr(state->bar_state), 1);

    /* Free htables */
    v3_free_htable(state->htg_table, 0, 0);
    v3_free_htable(state->gth_table, 0, 0);

    /* Free state */
    V3_Free(state);

    return 0;
}

static struct v3_device_ops dev_ops = {
    .free = xpmem_free,
};



static int
irq_ack(struct v3_core_info * core, 
	uint32_t              irq,
	void                * private_data)
{
    struct v3_xpmem_state * state   = (struct v3_xpmem_state *)private_data;
    struct pci_device     * pci_dev = state->pci_dev;
    struct vm_device      * pci_bus = state->pci_bus;

    v3_pci_lower_irq(pci_bus, pci_dev, pci_dev->config_header.intr_line);

    return 0;
}

static int
xpmem_raise_irq(struct v3_xpmem_state * v3_xpmem)
{
    struct pci_device        * pci_dev = v3_xpmem->pci_dev;
    struct vm_device         * pci_bus = v3_xpmem->pci_bus;
    struct xpmem_cmd_ex_iter * iter    = NULL;

    /* Set up the bar */
    v3_spin_lock(&(v3_xpmem->lock));
    {
	iter = list_first_entry(&(v3_xpmem->cmd_list), struct xpmem_cmd_ex_iter, node);
    }
    v3_spin_unlock(&(v3_xpmem->lock));

    PrintDebug("Raising XPMEM irq for command %d\n", iter->cmd->type);

    /* Tell the guest to allocate a buffer if this is an attachment */
    if (iter->cmd->type == XPMEM_ATTACH) {
	v3_xpmem->bar_state->xpmem_pfn_size = iter->cmd->attach.num_pfns * sizeof(uint32_t);
    } else {
	v3_xpmem->bar_state->xpmem_pfn_size = 0;
    }

    v3_xpmem->bar_state->xpmem_cmd_size = sizeof(struct xpmem_cmd_ex);
    v3_xpmem->bar_state->irq_handled    = 0;

    if (pci_dev->irq_type == IRQ_NONE) {
        PrintError("XPMEM: no IRQ type set\n");
        return -1;
    } else if (pci_dev->irq_type == IRQ_INTX) { 
	struct v3_irq vec;
        vec.irq = pci_dev->config_header.intr_line;
        vec.ack = irq_ack;
        vec.private_data = v3_xpmem;

        v3_pci_raise_acked_irq(pci_bus, pci_dev, vec);
    } else {
        v3_pci_raise_irq(pci_bus, pci_dev, 0); 
    }   

    return 0;
}

static int
copy_guest_regs(struct v3_xpmem_state * state, 
		struct v3_core_info   * core, 
		struct xpmem_cmd_ex   * host_cmd)
{
    addr_t cmd_gva = core->vm_regs.rbx;
    size_t bytes   = sizeof(struct xpmem_cmd_ex);
    size_t read    = 0;

    /* Translate guest command structure address to host address */
    read = v3_read_gva(
	core,
	cmd_gva,
	bytes,
	(uint8_t *)host_cmd
    );

    if (read < bytes) {
	PrintError("v3_read_gva failed (read %lu bytes out of %lu)\n", read, bytes);
	return -1;
    }

    if (host_cmd->type == XPMEM_ATTACH) {

	/* If this is an attachment, we need to do two things:
	 * (1) Allocate a list in host memory to store the page frames that are eventually
	 * mapped by the remote domain. Set the list pointer in the command struct to the
	 * host address
	 *
	 * (2) Cache the reverse host->guest translation in a hashtable.
	 */

	addr_t     pfn_list_gpa = host_cmd->attach.pfn_pa;
	addr_t     pfn_list_hpa = 0;
	uint32_t * pfns         = NULL;
	size_t     list_size    = host_cmd->attach.num_pfns * sizeof(uint32_t);

	/* We need to allocate a new list in the host instead of just using the base
	 * region underlying the guest list, because the host regions might not be
	 * physically contiguous
	 */
	pfns = V3_Malloc(list_size);
	if (pfns == NULL) {
	    PrintError("XPMEM: out of memory\n");
	    return -1;
	}

	pfn_list_hpa = (addr_t)V3_PAddr((void *)pfns);

        /* Cache the reverse translation */
	if (v3_htable_insert(state->htg_table, pfn_list_hpa, pfn_list_gpa) == 0) {
	    PrintError("v3_htable_insert failed\n");
	    V3_Free(pfns);
	    return -1;
	}

        /* Update the command struct to point to host memory */
	host_cmd->attach.pfn_pa = (uint64_t)pfn_list_hpa;
    } else if (host_cmd->type == XPMEM_ATTACH_COMPLETE) {

	/* If this is an attachment completion, we do two things:
	 * (1) Copy the list provided by the guest to a a host-accessible list, which can
	 * be directly accessed by all native enclaves. The host list has already been
	 * allocated and can be found in the translation table. Remove the translation
	 *
	 * (2) Modify each pfn, which refers to guest physical memory, to the associated
	 * host pfn by walking the shadow map
	 */

	int        i            = 0;
	addr_t     pfn_list_gpa = host_cmd->attach.pfn_pa;
	addr_t     pfn_list_hpa = 0;
	uint32_t * pfns         = NULL;

	bytes = host_cmd->attach.num_pfns * sizeof(uint32_t);

        /* Convert the guest page list pointer to a host address */
	pfn_list_hpa = v3_htable_remove(state->gth_table, (addr_t)pfn_list_gpa, 0);
	if (pfn_list_hpa == 0) {
	    PrintError("Cannot convert guest pfn list %p to host list\n", (void *)pfn_list_gpa);
	    return -1;
	}

	/* Get the host pfn list from the pfn_list_hpa */
	pfns = (uint32_t *)V3_VAddr((void *)pfn_list_hpa);
	if (pfns == NULL) {
	    PrintError("Cannot map host pa %p\n", (void *)pfn_list_hpa);
	    return -1;
	}

        /* Copy the guest list into the host */
	read = v3_read_gpa(
	    core,
	    pfn_list_gpa,
	    bytes,
	    (uint8_t *)pfns
	);

	if (read < bytes) {
	    PrintError("v3_read_gpa failed (read %lu bytes out of %lu)\n", read, bytes);
	    return -1;
	}

        /* Convert each guest pfn to a host pfn */
	for (i = 0; i < host_cmd->attach.num_pfns; i++) {
	    uint32_t guest_pfn   = pfns[i];
	    addr_t   guest_paddr = 0;
	    addr_t   host_paddr  = 0;

	    guest_paddr = xpmem_pfn_to_paddr(guest_pfn);

	    if (v3_gpa_to_hpa(core, guest_paddr, &host_paddr) != 0) {
		PrintError("v3_gpa_to_hpa failed (gpa=%p)\n", (void *)guest_paddr);
		return -1;
	    }

            /* Update the list */
	    pfns[i] = xpmem_paddr_to_pfn(host_paddr);

	    PrintDebug("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
		(unsigned long long)guest_pfn,
		(unsigned long long)pfns[i],
		(void *)guest_paddr,
		(void *)host_paddr
	    );
	}

        /* Update the command struct to point to host memory */
	host_cmd->attach.pfn_pa = (uint64_t)pfn_list_hpa;
    } 

    return 0;
}

static int
xpmem_hcall(struct v3_core_info * core,
	    hcall_id_t            hcall_id,
	    void                * priv_data)
{
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex     cmd;

    if (copy_guest_regs(state, core, &cmd)) {
        PrintError("XPMEM: failed to copy guest registers\n");
        return -1;
    }

    /* Returning -1 on hypercalls kills the guest */
    (void)v3_xpmem_host_command(state->host_handle, &cmd);

    return 0;
}

static int
xpmem_detach_hcall(struct v3_core_info * core,
                   hcall_id_t            hcall_id,
		   void                * priv_data)
{
    struct v3_xpmem_state    * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_memory_region region;

    int    status = 0;
    addr_t len    = 0;
    addr_t gpa    = (addr_t)core->vm_regs.rbx;

    status = xpmem_find_and_remove_allocated_region(
        state, 
	gpa, 
	&region
    );

    if (status != 0) {
	PrintError("XPMEM: cannot find region at address %p in guest shadow map\n",
	     (void *)gpa);
	return 0;
    }

    len = region.guest_end - region.guest_start;

    status = xpmem_insert_free_memory_region(
	state, 
	region.guest_start, 
	len
    );

    if (status != 0) {
	PrintError("XPMEM: cannot insert region [%p, %p) into guest free list\n",
	     (void *)region.guest_start, (void *)(region.guest_end));
	return 0;
    }

    status = xpmem_remove_shadow_region(
        state, 
	region.guest_start, 
	len
    );

    if (status != 0) {
	PrintError("XPMEM: cannot shadow remove region [%p, %p) from guest memory map\n",
	     (void *)region.guest_start, (void *)(region.guest_end));
	return 0;
    }

    return 0;
}

static int
xpmem_irq_clear_hcall(struct v3_core_info * core,
                      hcall_id_t            hcall_id,
		      void                * priv_data)
{
    struct v3_xpmem_state    * state     = (struct v3_xpmem_state *)priv_data;
    int                        raise_irq = 0;
    int                        ret       = 0;

    v3_spin_lock(&(state->lock));
    {
	state->bar_state->xpmem_cmd_size = 0;
	state->bar_state->irq_handled    = 1;

	if (!list_empty(&(state->cmd_list))) {
	    raise_irq = 1;
	}
    }
    v3_spin_unlock(&(state->lock));

    if (raise_irq) {
	ret = xpmem_raise_irq(state);
    }

    return ret;

}


static int 
xpmem_map_host_pages(struct v3_xpmem_state * v3_xpmem,
                     struct v3_core_info   * core,
                     uint64_t                num_pfns,
                     addr_t                  pfn_list_hpa,
		     addr_t                  pfn_list_gpa)
{
    /* Get the host pfn list from the pfn_list_hpa */
    uint32_t * pfn_list = (uint32_t *)V3_VAddr((void *)pfn_list_hpa);

    size_t bytes = num_pfns * sizeof(uint32_t);
    size_t wrote = 0;
    int    ret   = 0; 

    /* Update mem map for the new host PFNs. This will modify the pfn_list to hold the
     * guest PFNs */
    if (xpmem_add_shadow_region(v3_xpmem, num_pfns, pfn_list) != 0) {
	V3_Free(pfn_list);
	return -1;
    }

    wrote = v3_write_gpa(
	core,
	pfn_list_gpa,
	bytes,
	(uint8_t *)pfn_list
    );

    if (wrote < bytes) {
	PrintError("v3_write_gpa failed (wrote %llu bytes out of %llu)\n",
	    (unsigned long long)wrote, (unsigned long long)bytes);
	xpmem_remove_shadow_region(v3_xpmem, (addr_t)pfn_list[0], num_pfns); 
	ret = -1;
    }

    /* Free the pfn list */
    V3_Free(pfn_list);

    return ret;
}


static int
xpmem_read_cmd_hcall(struct v3_core_info * core,
                     hcall_id_t            hcall_id,
		     void                * priv_data)
{
    struct v3_xpmem_state    * state     = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex_iter * iter      = NULL; 
    int                        cmd_ready = 0;
    int                        ret       = 0;
    addr_t                     cmd_gva   = core->vm_regs.rbx;
    size_t                     bytes     = 0;
    size_t                     wrote     = 0;

    v3_spin_lock(&(state->lock));
    {
	if (!list_empty(&(state->cmd_list))) {
	    iter = list_first_entry(&(state->cmd_list), struct xpmem_cmd_ex_iter, node);
	    list_del(&(iter->node));
	    cmd_ready = 1;
	}
    }
    v3_spin_unlock(&(state->lock));

    /* The guest should not be reading a command when there's nothing pending */
    if (!cmd_ready) {
	return -1;
    }

    if (iter->cmd->type == XPMEM_ATTACH) {
	/* On attachments, the guest specifies the address of a list where it plans
	 * to eventually write the guest PFNS. We need to remember the translation from
	 * guest to host so that we can copy to host memory on attachment completion
	 */
	addr_t pfn_list_gpa = core->vm_regs.rcx;
	addr_t pfn_list_hpa = iter->cmd->attach.pfn_pa;

        /* Cache the translation */
	if (v3_htable_insert(state->gth_table, pfn_list_gpa, pfn_list_hpa) == 0) {
	    PrintError("v3_htable_insert failed\n");
	    ret = -1;
	    goto out;
	}
    } else if (iter->cmd->type == XPMEM_ATTACH_COMPLETE) {
	/* On attachment complettions, we do 2 things:
	 *
	 * (1) Allocate a __new__ guest physical address range that spans the size of the
	 * requested attachment.
	 *
	 * (2) Map the new guest region to the host pfns, and conver the pfn list to the
	 * new guest pfns 
	 */
	addr_t pfn_list_hpa = iter->cmd->attach.pfn_pa;
	addr_t pfn_list_gpa = 0;

	/* The pfn list was already allocated by the guest, and pfn_list_hpa is the hpa of
	 * the list pointer. Query the host->guest map to find the guest address, and
	 * remove the mapping
	 */
	pfn_list_gpa = v3_htable_remove(state->htg_table, (addr_t)pfn_list_hpa, 0);
	if (pfn_list_gpa == 0) {
	    PrintError("Cannot convert host pfn list %p to guest list\n", (void *)pfn_list_hpa);
	    ret = -1;
	    goto out;
	}
	
	/* Perform the translation */
        if (xpmem_map_host_pages(state, core, iter->cmd->attach.num_pfns, pfn_list_hpa, pfn_list_gpa) != 0) {
	    PrintError("XPMEM: cannot update guest shadow map\n");
	    ret = -1;
	    goto out;
	}

	/* Store the GPA in the command struct */
	iter->cmd->attach.pfn_pa = (uint64_t)pfn_list_gpa;
    }

    /* Write the command to the guest */
    bytes = sizeof(struct xpmem_cmd_ex);
    wrote = v3_write_gva(core, cmd_gva, bytes, (uint8_t *)iter->cmd);

    if (wrote < bytes) {
	PrintError("v3_write_gva failed (wrote %llu bytes out of %llu)\n",
	    (unsigned long long)wrote, (unsigned long long)bytes);
	ret = -1;
	goto out;
    }

out:
    V3_Free(iter->cmd);
    V3_Free(iter);

    return ret;
}

static int
register_xpmem_dev(struct v3_xpmem_state * state)
{
    struct v3_pci_bar   bars[6];
    struct pci_device * pci_dev = NULL;

    if (state->pci_bus == NULL) {
        PrintError("XPMEM: Not attached to any PCI bus!\n");
        return -1;
    }

    {
        int i = 0;
	for (i = 0; i < 6; i++) {
	    bars[i].type = PCI_BAR_NONE;
	}
    }

    bars[0].type              = PCI_BAR_MEM32;
    bars[0].num_pages         = 1;
    bars[0].mem_read          = NULL;
    bars[0].mem_write         = NULL;
    bars[0].default_base_addr = 0xffffffff;
    bars[0].host_base_addr    = (addr_t)V3_PAddr(state->bar_state);

    pci_dev = v3_pci_register_device(state->pci_bus,
            PCI_STD_DEVICE,
            0, PCI_AUTO_DEV_NUM, 0,
            "XPMEM", bars,
            NULL, NULL, NULL, NULL, 
            state);

    if (pci_dev == NULL) {
        PrintError("XPMEM: Could not register PCI device\n");
        return -1;
    }

    pci_dev->config_header.vendor_id           = XPMEM_VENDOR_ID;
    pci_dev->config_header.subsystem_vendor_id = XPMEM_SUBVENDOR_ID;
    pci_dev->config_header.device_id           = XPMEM_DEV_ID;

    pci_dev->config_header.class        = PCI_CLASS_MEMORY;
    pci_dev->config_header.subclass     = PCI_MEM_SUBCLASS_OTHER;
    pci_dev->config_header.subsystem_id = XPMEM_SUBDEVICE_ID;
    pci_dev->config_header.intr_pin     = 1; 

    state->pci_dev = pci_dev;

    return 0;
}


static uint_t
xpmem_hash_fn(addr_t key)
{
    return v3_hash_long(key, sizeof(addr_t));
}

static int
xpmem_eq_fn(addr_t key1,
            addr_t key2)
{
    return (key1 == key2);
}


static int
xpmem_init(struct v3_vm_info * vm, 
           v3_cfg_tree_t     * cfg)
{
    struct vm_device      * pci_bus = v3_find_dev(vm, v3_cfg_val(cfg, "bus"));
    struct vm_device      * dev     = NULL;
    char                  * dev_id  = v3_cfg_val(cfg, "ID");
    struct v3_xpmem_state * state   = NULL;
    addr_t                  bar_pa  = 0;

    state = (struct v3_xpmem_state *)V3_Malloc(sizeof(struct v3_xpmem_state));
    if (state == NULL) {
        PrintError("Cannot allocate state for xpmem device\n");
        return -1;
    }

    memset(state, 0, sizeof(struct v3_xpmem_state));
    state->pci_bus = pci_bus;
    state->vm      = vm;

    dev = v3_add_device(vm, dev_id, &dev_ops, state);
    if (dev == NULL) {
        PrintError("Could not attach device %s\n", dev_id);
        V3_Free(state);
        return -1;
    }

    bar_pa           = (addr_t)V3_AllocPages(1);
    state->bar_state = V3_VAddr((void *)bar_pa);

    /* SVM or VMX? */
    state->bar_state->svm_capable = (v3_is_svm_capable() > 0);
    state->bar_state->vmx_capable = (v3_is_vmx_capable() > 0);

    /* Save hypercall ids in the bar */
    state->bar_state->xpmem_hcall_id           = XPMEM_HCALL;
    state->bar_state->xpmem_detach_hcall_id    = XPMEM_DETACH_HCALL;
    state->bar_state->xpmem_irq_clear_hcall_id = XPMEM_IRQ_CLEAR_HCALL;
    state->bar_state->xpmem_read_cmd_hcall_id  = XPMEM_READ_CMD_HCALL;

    /* Setup other bar information */
    state->bar_state->xpmem_cmd_size = 0;
    state->bar_state->xpmem_pfn_size = 0;
    state->bar_state->irq_handled    = 0;

    /* Register hypercall callbacks with Palacios */
    v3_register_hypercall(vm, XPMEM_HCALL, xpmem_hcall, state);
    v3_register_hypercall(vm, XPMEM_DETACH_HCALL, xpmem_detach_hcall, state);
    v3_register_hypercall(vm, XPMEM_IRQ_CLEAR_HCALL, xpmem_irq_clear_hcall, state);
    v3_register_hypercall(vm, XPMEM_READ_CMD_HCALL, xpmem_read_cmd_hcall, state);

    /* Misc setup */
    v3_spinlock_init(&(state->lock));
    INIT_LIST_HEAD(&(state->cmd_list));
    state->htg_table = v3_create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    state->gth_table = v3_create_htable(0, xpmem_hash_fn, xpmem_eq_fn);

    /* Initialize guest memory map */
    if (init_xpmem_mem_map(state) != 0) {
	PrintError("Could not initialize XPMEM guest memory map\n");
	V3_Free(state);
	return -1;
    }

    /* Initialize host channel */
    state->host_handle = v3_xpmem_host_connect(vm, state);
    if (!state->host_handle) {
        PrintError("Could not initialized XPMEM host channel\n");
        V3_Free(state);
        return -1;
    }

    /* Register with Palacios */
    if (register_xpmem_dev(state)) {
        PrintError("Could not register XPMEM device %s\n", dev_id);
        return -1;
    }

    PrintDebug("Registered XPMEM device\n");

    return 0;
}


/*
 * Deliver an XPMEM command into the guest.
 *
 * If the guest is not currently processing a command, we can put this directly
 * into the BAR and raise an IRQ.
 *
 * If the guest is currently processing a command, we need to put this on a list
 * and raise the interrupt when the guest finishes processing the command
 */
int 
v3_xpmem_command(struct v3_xpmem_state * v3_xpmem, 
                 struct xpmem_cmd_ex   * cmd)
{
    struct xpmem_cmd_ex_iter * iter =  NULL;

    iter = (struct xpmem_cmd_ex_iter *)V3_Malloc(sizeof(struct xpmem_cmd_ex_iter));
    if (!iter) {
	PrintError("XPMEM: out of memory\n");
	return -1;
    }

    iter->cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));
    if (!iter->cmd) {
	PrintError("XPMEM: out of memory\n");
	V3_Free(iter);
	return -1;
    }

    /* Copy host command structure into iterator */
    memcpy(iter->cmd, cmd, sizeof(struct xpmem_cmd_ex));

    /* Add to the command list */
    {
	int raise_irq = 0;

        v3_spin_lock(&(v3_xpmem->lock));
	{
	    list_add_tail(&(iter->node), &(v3_xpmem->cmd_list));

	    if (v3_xpmem->bar_state->irq_handled) {
		raise_irq = 1;
	    }
	}
	v3_spin_unlock(&(v3_xpmem->lock));

	if (raise_irq) {
	    /* Raise the IRQ */ 
	    return xpmem_raise_irq(v3_xpmem);
	}		
    }

    return 0;
}

int
v3_xpmem_raise_irq(struct v3_xpmem_state * v3_xpmem,
                   int                     vector)
{
    return 0;
}

device_register("XPMEM", xpmem_init)
