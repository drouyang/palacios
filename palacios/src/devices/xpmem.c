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

#define GUEST_DEFAULT_BAR   0xe0000000


struct xpmem_bar_state {
    /* Hypercall numbers */
    uint32_t xpmem_hcall_id;
    uint32_t xpmem_detach_hcall_id;
    uint32_t xpmem_irq_clear_hcall_id;
    uint32_t xpmem_read_cmd_hcall_id;
 
    /* interrupt status */
    uint8_t irq_handled;

    /* size of xpmem cmd size */
    uint64_t xpmem_cmd_size;
  
    /* size of xpmem pfn list */
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
    struct v3_core_info * core;

    /* state lock */
    v3_spinlock_t            lock;

    /* handle to host state */
    xpmem_host_handle_t      host_handle;

    /* bar exposed to guest */
    struct xpmem_bar_state * bar_state;

    /* list of XPMEM commands to be delivered to the guest */
    struct list_head         cmd_list;

    /* guest XPMEM memory map */
    struct xpmem_memory_map  mem_map;
};

struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    struct list_head      node;
};


/*
 * List insert function. We insert the region [addr, addr + len) into list,
 * merging with other entries in the list when possible 
 */
static int
xpmem_insert_memory_region(struct list_head           * list,
			   addr_t                       addr,
			   uint64_t                     len)
{
    struct xpmem_memory_region * iter      = NULL;
    struct xpmem_memory_region * prev_iter = NULL;
    struct xpmem_memory_region * next      = NULL;
    struct xpmem_memory_region * new_reg   = NULL;

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

// 1 TB: Start of XPMEM range
#define XPMEM_MEM_START (1ULL << 40)

// 1 TB of addressable XPMEM
#define XPMEM_MEM_END   (1ULL << 41)

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
    return xpmem_insert_memory_region(&(mem_map->free_list), XPMEM_MEM_START, (XPMEM_MEM_END - XPMEM_MEM_START));
}


/* Find region of len bytes */
static int
xpmem_find_space(struct list_head * list,
                 uint64_t           len,
	         addr_t           * addr)
{
    struct xpmem_memory_region * iter = NULL;
    struct xpmem_memory_region * next = NULL;

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
xpmem_find_and_remove_region(struct list_head           * list,
                             addr_t                       addr,
		             struct xpmem_memory_region * region)
{
    struct xpmem_memory_region * iter = NULL;
    struct xpmem_memory_region * next = NULL;

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


/*
 * Map host pfns stored in pfn_list to guest memory
 */
static int
xpmem_add_shadow_region(struct v3_xpmem_state * state,
                        uint64_t              * pfn_list,
			uint64_t                num_pfns,
			addr_t                * guest_addr_p)
{
    struct xpmem_memory_map * mem_map    = &(state->mem_map);
    int                       status     = 0;
    addr_t                    region_len = 0;
    addr_t                    start_addr = 0;

    region_len = (addr_t)(num_pfns * PAGE_SIZE);

    /* Search for free space */
    status = xpmem_find_space(&(mem_map->free_list), region_len, &start_addr);
    if (status != 0) {
	PrintError("XPMEM: cannot find free region of %llu bytes: "
		"cannot map host memory\n", (unsigned long long)region_len);
	return -1;
    }

    /* Map region into guest. The host range may be discontiguous, so we have to
     * do this a page at a time
     */
    {
	uint64_t i = 0;

	for (i = 0; i < num_pfns; i++) {
	    addr_t guest_addr = start_addr + (i * PAGE_SIZE);
	    addr_t host_addr  = (addr_t)(pfn_list[i] << 12);

	    status = v3_add_shadow_mem(state->vm,
		V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
		guest_addr,
		guest_addr + PAGE_SIZE,
		host_addr
	    );

	    if (status != 0) {
		PrintError("XPMEM: could not add shadow memory region!\n");
		
		/* Undo whatever mappings were done */
		for (i--; i >= 0; i--) {
		    struct v3_mem_region * old_reg = NULL;

		    guest_addr = start_addr + (i * PAGE_SIZE);
		    old_reg    = v3_get_mem_region(state->vm, V3_MEM_CORE_ANY, guest_addr);

		    v3_delete_mem_region(state->vm, old_reg);
		}

		xpmem_insert_memory_region(&(mem_map->free_list), start_addr, region_len);
		return -1;
	    }
	}

	/* OK, the shadow mapping is done - update the alloc list */
	status = xpmem_insert_memory_region(&(mem_map->alloc_list), start_addr, region_len);
	if (status != 0) {
	    PrintError("XPMEM: cannot add region [%p, %p) to guest alloc list\n",
		    (void *)start_addr, (void *)(start_addr + region_len));
	    return -1;
	}
    }
    
    *guest_addr_p = start_addr;
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
    struct pci_device * pci_dev = v3_xpmem->pci_dev;
    struct vm_device  * pci_bus =  v3_xpmem->pci_bus;


    /* Set up the bar */
    {
	struct xpmem_cmd_ex_iter * iter =
		list_first_entry(&(v3_xpmem->cmd_list), struct xpmem_cmd_ex_iter, node);

	PrintDebug("Raising XPMEM irq for command %d\n", iter->cmd->type);

	if (iter->cmd->type == XPMEM_ATTACH_COMPLETE) {
	    v3_xpmem->bar_state->xpmem_pfn_size = iter->cmd->attach.num_pfns * sizeof(uint64_t);
	} else {
	    v3_xpmem->bar_state->xpmem_pfn_size = 0;
	}

	v3_xpmem->bar_state->xpmem_cmd_size = sizeof(struct xpmem_cmd_ex);
	v3_xpmem->bar_state->irq_handled    = 0;
    }

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
		struct xpmem_cmd_ex  ** host_cmd_p)
{
    struct xpmem_cmd_ex * cmd            = NULL;
    struct xpmem_cmd_ex * host_cmd       = NULL;
    addr_t                guest_cmd_addr = 0;
    addr_t                host_cmd_addr  = 0;

    guest_cmd_addr = core->vm_regs.rbx;
    *host_cmd_p    = NULL;

    /* Translate guest command structure address to host address */
    if (v3_gva_to_hva(core, guest_cmd_addr, (addr_t *)&host_cmd_addr)) {
	PrintError("XPMEM: Unable to convert guest command address to host address"
	           " (GVA: %p)\n", (void *)guest_cmd_addr);
	return -1;
    }

    /* Grab the command */
    cmd = (struct xpmem_cmd_ex *)host_cmd_addr;

    host_cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));
    if (!host_cmd) {
	PrintError("XPMEM: out of memory\n");
	return -1;
    }

    /* Copy guest command structure into host memory */
    memcpy(host_cmd, cmd, sizeof(struct xpmem_cmd_ex));


    /* Translate guest PFNs to host PFNs if this is an attachment completion */
    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
	int i = 0;

        /* Allocate memory for the pfn list */
	host_cmd->attach.pfns = V3_Malloc(sizeof(uint64_t) * cmd->attach.num_pfns);
	if (!host_cmd->attach.pfns) {
	    PrintError("XPMEM: out of memory\n");
	    V3_Free(host_cmd);
	    return -1;
	}

	for (i = 0; i < cmd->attach.num_pfns; i++) {
	    void *   guest_pfn_list_base       = (void *)cmd->attach.pfns;
	    addr_t   guest_pfn_list_entry      = (addr_t)(guest_pfn_list_base + (i * sizeof(uint64_t)));
	    addr_t   guest_pfn_list_entry_host = 0;
	    uint64_t guest_pfn                 = 0;

	    /* guest_pfn_list_entry is the guest virtual address of the list
	     * entry storing the 'ith' guest page frame number
	     */
	    
	    /* Convert list element to host accessible element */
	    if (v3_gva_to_hva(core, guest_pfn_list_entry, &guest_pfn_list_entry_host)) {
		PrintError("XPMEM: Unable to convert guest pfn list entry to host address"
			   " (GVA: %p)\n", (void *)guest_pfn_list_entry);
		V3_Free(host_cmd);
		return -1;
	    }

	    guest_pfn = *((uint64_t *)guest_pfn_list_entry_host);

	    {
		addr_t guest_paddr = (addr_t)(guest_pfn << 12);
		addr_t host_paddr  = 0;
		
		if (v3_gpa_to_hpa(core, guest_paddr, &host_paddr)) {
		    PrintError("XPMEM: Unable to convert guest PFN to host PFN"
			       " (GPA: %p)\n", (void *)guest_paddr);
		    V3_Free(host_cmd);
		    return -1;
		}

		host_cmd->attach.pfns[i] = (uint64_t)(host_paddr >> 12);

		PrintDebug("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
		    (unsigned long long)guest_pfn,
		    (unsigned long long)host_cmd->attach.pfns[i],
		    (void *)guest_paddr,
		    (void *)host_paddr
		);
	    }
	}
    } 

    *host_cmd_p = host_cmd;
    return 0;
}


static int
xpmem_hcall(struct v3_core_info * core,
	    hcall_id_t            hcall_id,
	    void                * priv_data)
{
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex   * cmd   = NULL;
    int                     ret   = 0;

    if (copy_guest_regs(state, core, &cmd)) {
        PrintError("XPMEM: failed to copy guest registers\n");
        return -1;
    }

    ret = v3_xpmem_host_command(state->host_handle, cmd);

    V3_Free(cmd);

    return ret;
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

    status = xpmem_find_and_remove_region(&(state->mem_map.alloc_list), gpa, &region);
    if (status != 0) {
	PrintError("XPMEM: cannot find region at address %p in guest shadow map\n",
	     (void *)gpa);
	return 0;
    }

    len = region.guest_end - region.guest_start;

    status = xpmem_insert_memory_region(&(state->mem_map.free_list), region.guest_start, len);
    if (status != 0) {
	PrintError("XPMEM: cannot insert region [%p, %p) into guest free list\n",
	     (void *)region.guest_start, (void *)(region.guest_end));
	return 0;
    }

    status = xpmem_remove_shadow_region(state, region.guest_start, len);
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
    unsigned long              flags     = 0;
    int                        raise_irq = 0;
    int                        ret       = 0;

    flags = v3_spin_lock_irqsave(&(state->lock));
    {
	state->bar_state->xpmem_cmd_size = 0;
	state->bar_state->xpmem_pfn_size = 0;
	state->bar_state->irq_handled    = 1;

	if (!list_empty(&(state->cmd_list))) {
	    raise_irq = 1;
	}
    }
    v3_spin_unlock_irqrestore(&(state->lock), flags);

    if (raise_irq) {
	ret = xpmem_raise_irq(state);
    }

    return ret;

}

static int
xpmem_read_cmd_hcall(struct v3_core_info * core,
                     hcall_id_t            hcall_id,
                     void                * priv_data)
{
    struct v3_xpmem_state    * state     = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex_iter * iter      = NULL; 
    unsigned long              flags     = 0;
    int                        cmd_ready = 0;


    flags = v3_spin_lock_irqsave(&(state->lock));
    {
	if (!list_empty(&(state->cmd_list))) {
	    iter = list_first_entry(&(state->cmd_list), struct xpmem_cmd_ex_iter, node);
	    list_del(&(iter->node));
	    cmd_ready = 1;
	}
    }
    v3_spin_unlock_irqrestore(&(state->lock), flags);

    /* The guest should not be reading a command when there's nothing pending */
    if (!cmd_ready) {
	return -1;
    }


    {
	addr_t guest_buf      = core->vm_regs.rbx;
	addr_t guest_buf_host = 0;

	if (v3_gva_to_hva(core, guest_buf, &guest_buf_host)) {
	    PrintError("XPMEM: Unable to convert guest command buffer to host address"
		       " (GPA: %p)\n", (void *)guest_buf);
	    return -1;
	}

	memcpy((void *)guest_buf_host, iter->cmd, sizeof(struct xpmem_cmd_ex));

        /* The guest specifies an additional buffer for attachment lists */
	if (iter->cmd->type == XPMEM_ATTACH_COMPLETE) {
	    uint64_t i             = 0;
	    addr_t   guest_pfn_buf = core->vm_regs.rcx;

	    for (i = 0; i < iter->cmd->attach.num_pfns; i++) {
		void * guest_pfn_buf_base          = (void *)guest_pfn_buf;
		addr_t guest_pfn_buf_entry         = (addr_t)(guest_pfn_buf_base + (i * sizeof(uint64_t)));
		addr_t guest_pfn_buf_entry_host    = 0;

		if (v3_gva_to_hva(core, guest_pfn_buf_entry, &guest_pfn_buf_entry_host)) {
		    PrintError("XPMEM: Unable to convert guest command pfn list buffer to host address"
			       " (GPA: %p)\n", (void *)guest_pfn_buf_entry);
		    return -1;
		}

                /* Copy the pfn in */
		*((uint64_t *)guest_pfn_buf_entry_host) = iter->cmd->attach.pfns[i];
	    }

	    V3_Free(iter->cmd->attach.pfns);
	}

	V3_Free(iter->cmd);
	V3_Free(iter);
    }

    return 0;
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

    bars[0].type = PCI_BAR_MEM32;
    bars[0].num_pages = 1;
    bars[0].mem_read = NULL;
    bars[0].mem_write = NULL;
    bars[0].default_base_addr = GUEST_DEFAULT_BAR;

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

    if (v3_add_shadow_mem(state->vm, V3_MEM_CORE_ANY, V3_MEM_RD,
                GUEST_DEFAULT_BAR,
                GUEST_DEFAULT_BAR + PAGE_SIZE,
                bar_pa)) {
        PrintError("Failed to add XPMEM shadow BAR region\n");
    }

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

    v3_spinlock_init(&(state->lock));
    INIT_LIST_HEAD(&(state->cmd_list));

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
    struct xpmem_cmd_ex_iter * iter    =  NULL;
    unsigned long              flags   = 0;
    uint64_t                   pfn_len = 0;
    int                        ret     = 0;


    iter = (struct xpmem_cmd_ex_iter *)V3_Malloc(sizeof(struct xpmem_cmd_ex_iter));
    if (!iter) {
	PrintError("XPMEM: out of memory\n");
	return -1;
    }

    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
	pfn_len = cmd->attach.num_pfns * sizeof(uint64_t);
    }

    iter->cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));
    if (!iter->cmd) {
	PrintError("XPMEM: out of memory\n");
	V3_Free(iter);
	return -1;
    }

    /* Copy host command structure into iterator */
    memcpy(iter->cmd, cmd, sizeof(struct xpmem_cmd_ex));

    /* Translate host PFNs to guest PFNs if this is an attachment completion */
    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
        addr_t guest_start_addr = 0;
	int    status           = 0;

        /* Update shadow map for the new host PFNs */
	status = xpmem_add_shadow_region(
	    v3_xpmem,
	    cmd->attach.pfns,
	    cmd->attach.num_pfns,
	    &guest_start_addr);

        if (status != 0) {
            PrintError("XPMEM: cannot update guest shadow map\n");
	    V3_Free(iter->cmd);
	    V3_Free(iter);
            return -1;
        }

        /* Allocate memory for the pfn list */
	iter->cmd->attach.pfns = V3_Malloc(sizeof(uint64_t) * cmd->attach.num_pfns);
	if (!iter->cmd->attach.pfns) {
	    PrintError("XPMEM: out of memory\n");
	    V3_Free(iter->cmd);
	    V3_Free(iter);
	    return -1;
	}

        {
            int i = 0;

            for (i = 0; i < cmd->attach.num_pfns; i++) {
                addr_t guest_paddr = guest_start_addr + (i * PAGE_SIZE);

		iter->cmd->attach.pfns[i] = (uint64_t)(guest_paddr >> 12);

                PrintDebug("Host PFN %llu ---> Guest PFN %llu (%p -> %p)\n",
                    (unsigned long long)cmd->attach.pfns[i],
                    (unsigned long long)iter->cmd->attach.pfns[i],
                    (void *)(cmd->attach.pfns[i] << 12),
                    (void *)guest_paddr
                );
            }
        }
    }

    /* Add to the command list */
    {
	int raise_irq = 0;

        flags = v3_spin_lock_irqsave(&(v3_xpmem->lock));
	{
	    list_add_tail(&(iter->node), &(v3_xpmem->cmd_list));

	    if (v3_xpmem->bar_state->irq_handled) {
		raise_irq = 1;
	    }
	}
	v3_spin_unlock_irqrestore(&(v3_xpmem->lock), flags);


	if (raise_irq) {
	    /* Raise the IRQ */ 
	    ret = xpmem_raise_irq(v3_xpmem);
	}	
    }

    return ret;
}


device_register("XPMEM", xpmem_init)
