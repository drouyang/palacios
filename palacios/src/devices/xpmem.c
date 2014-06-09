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


#if V3_CONFIG_DEBUG_XPMEM == 1
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
    uint32_t xpmem_irq_clear_hcall_id;
    uint32_t xpmem_read_cmd_hcall_id;
 
    /* interrupt status */
    uint8_t irq_handled;

    /* size of xpmem cmd */
    uint64_t xpmem_cmd_size;
};


struct v3_xpmem_state {
    struct v3_vm_info   * vm;
    struct vm_device    * pci_bus;
    struct pci_device   * pci_dev;
    struct v3_core_info * core;

    /* state lock */
    v3_spinlock_t lock;

    /* handle to host state */
    xpmem_host_handle_t host_handle;

    /* bar exposed to guest */
    struct xpmem_bar_state * bar_state;

    /* list of XPMEM commands to be delivered to the guest */
    struct list_head cmd_list;

    /* guest XPMEM memory map */
    struct list_head mem_map;
};

struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    uint64_t              cmd_size;
    struct list_head      node;
};

struct xpmem_mem_iter {
    addr_t guest_start;
    addr_t guest_end;
    struct list_head node;
};


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

	V3_Print("Raising XPMEM irq for command %d\n", iter->cmd->type);

	v3_xpmem->bar_state->xpmem_cmd_size = iter->cmd_size;
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
		struct xpmem_cmd_ex  ** host_cmd)
{
    struct xpmem_cmd_ex * cmd            = NULL;
    addr_t                guest_cmd_addr = 0;
    addr_t                host_cmd_addr  = 0;
    xpmem_op_t            type           = 0;

    type           = core->vm_regs.rbx;
    guest_cmd_addr = core->vm_regs.rcx;
    *host_cmd      = NULL;

    if (v3_gva_to_hva(core, guest_cmd_addr, (addr_t *)&host_cmd_addr)) {
	PrintError("XPMEM: Unable to convert guest command address to host address"
	           " (GVA: %p)\n", (void *)guest_cmd_addr);
	return -1;
    }

    cmd = (struct xpmem_cmd_ex *)host_cmd_addr;

    {
	uint64_t pfn_len = 0;

	if (cmd->type == XPMEM_ATTACH_COMPLETE) {
	    pfn_len = cmd->attach.num_pfns * sizeof(uint64_t);
	}

	*host_cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex) + pfn_len);
	if (!(*host_cmd)) {
	    PrintError("XPMEM: out of memory\n");
	    return -1;
	}

	/* Copy guest command structure into host memory */
	memcpy(*host_cmd, cmd, sizeof(struct xpmem_cmd_ex));

	/* Translate guest PFNs to host PFNs if this is an attachment completion */
	if (cmd->type == XPMEM_ATTACH_COMPLETE) {
	    int i = 0;

	    for (i = 0; i < cmd->attach.num_pfns; i++) {
		uint64_t guest_pfn   = cmd->attach.pfns[i];
		addr_t   guest_paddr = (addr_t)(guest_pfn << 12);
		addr_t   host_paddr  = 0;

		if (v3_gpa_to_hpa(core, guest_paddr, &host_paddr)) {
		    PrintError("XPMEM: Unable to convert guest PFN to host PFN"
		               " (GPA: %p)\n", (void *)guest_paddr);
		    V3_Free(*host_cmd);
		    return -1;
		}

		(*host_cmd)->attach.pfns[i] = (uint64_t)(host_paddr >> 12);

		PrintDebug("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
		    (unsigned long long)guest_pfn,
		    (unsigned long long)(*host_cmd)->attach.pfns[i],
		    (void *)guest_paddr,
		    (void *)host_paddr
		);
	    }
	} else if (cmd->type == XPMEM_DETACH) {
	    /* TODO: update guest shadow map */
	}
    }

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

    /* The guest should not be reading a command when there's nothing in it */
    if (!cmd_ready) {
	return -1;
    }

    {
	uint64_t cmd_size  = core->vm_regs.rbx;
	addr_t   guest_buf = core->vm_regs.rcx;
	addr_t   host_buf  = 0;

	if (cmd_size != state->bar_state->xpmem_cmd_size) {
	    PrintError("XPMEM: Guest trying to read invalid cmd size (%llu instead of %llu)\n",
		cmd_size, state->bar_state->xpmem_cmd_size);
	    return -1;
	}

	if (v3_gpa_to_hva(core, guest_buf, &host_buf)) {
	    PrintError("XPMEM: Unable to convert guest command buffer to host address"
		       " (GPA: %p)\n", (void *)guest_buf);
	    return -1;
	}

	memcpy((void *)host_buf, iter->cmd, cmd_size);

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


// 1 TB: Start of XPMEM range
#define XPMEM_MEM_START (1ULL << 40)
#define XPMEM_MEM_INCR  0x40000000LL

// 64 GB of addressable XPMEM
#define XPMEM_MEM_SIZE  (1ULL << 36)


/*
 * This all has to change, huge security problem, causes guests under 4GB to
 * die, etcetera
 */
#if 0
static int init_xpmem_mem_map(struct v3_xpmem_state * state) {
    INIT_LIST_HEAD(&(state->mem_map));
    addr_t try_addr = 0;

    for (try_addr = 0; try_addr < XPMEM_MAX_ADDR; try_addr += XPMEM_MEM_INCR) {
        if (!v3_add_shadow_mem(state->vm, 
                    V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
                    try_addr,
                    try_addr + XPMEM_MEM_SIZE,
                    0))
	{
            struct xpmem_mem_iter * iter = V3_Malloc(sizeof(struct xpmem_mem_iter));
            if (!iter) {
                PrintError("XPMEM: Out of memory\n");
                return -1;
            }

            iter->guest_start = try_addr;
            iter->guest_end = try_addr + XPMEM_MEM_SIZE;
            list_add(&(iter->node), &(state->mem_map));

            V3_Print("Guest XPMEM memory range: [%p, %p)\n",
                (void *)iter->guest_start,
                (void *)iter->guest_end
            );

            return 0;
        }
    }

    PrintError("Could not initialize guest XPMEM memory map: no available GPA space\n");
    return -1;
}

static addr_t alloc_mem_region(struct v3_xpmem_state * state, uint64_t size) {
    struct xpmem_mem_iter * free_iter = NULL, * free_next = NULL;

    list_for_each_entry_safe(free_iter, free_next, &(state->mem_map), node) {
        addr_t free_start = free_iter->guest_start;
        addr_t free_end = free_iter->guest_end;
        uint64_t free_size = free_end - free_start;
  
        if (free_size >= size) {
            /* Delete existing free region */
            {
                struct v3_mem_region * old_reg = v3_get_mem_region(state->vm, V3_MEM_CORE_ANY, free_start);
                if (!old_reg) {
                    PrintError("XPMEM: Cannot remove old guest shadow mapping - this should be impossible\n");
                    return 0;
                }
                v3_delete_mem_region(state->vm, old_reg);
            }

            if (size == free_size) {
                /* Exact fit */
                list_del(&(free_iter->node));
                V3_Free(free_iter);
            } else {
                /* Fix up hole */
                free_iter->guest_start = free_start + size;

                /* Re-insert NULL map */
                if (v3_add_shadow_mem(state->vm,
                        V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
                        free_iter->guest_start,
                        free_end,
                        0)) {
                    PrintError("XPMEM: Could not add free range to guest shadow map - this should be impossible!\n");
                    return 0;
                }
            }

            return free_start;
        }
    }

    PrintError("Could not carve XPMEM region from guest memory map\n");
    return 0;
}

static addr_t xpmem_add_shadow_map(struct v3_xpmem_state * state, uint64_t * pfns, uint64_t num_pfns) {
    uint64_t size = num_pfns * PAGE_SIZE;
    uint64_t i = 0;
    addr_t guest_start_addr = alloc_mem_region(state, size);

    if (!guest_start_addr) {
        return 0;
    }

    for (i = 0; i < num_pfns; i++) {
        addr_t guest_addr = guest_start_addr + (PAGE_SIZE * i);
        addr_t host_addr = (addr_t)pfns[i] << 12;

        if (v3_add_shadow_mem(state->vm, V3_MEM_CORE_ANY, V3_MEMRD | V3_MEM_WR,
                    guest_addr,
                    guest_addr + PAGE_SIZE,
                    host_addr)) {
            PrintError("XPMEM: Failed to add shadow PFN region (%p -> %p)\n",
                (void *)guest_addr,
                (void *)host_addr
            );
            return 0;
        }
    }

    return guest_start_addr;
}

/*
static int xpmem_remove_shadow_map(struct v3_xpmem_state * state, uint64_t * pfns, uint64_t num_pfns) {
    return 0;
}
*/
#endif

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
    state->bar_state->xpmem_irq_clear_hcall_id = XPMEM_IRQ_CLEAR_HCALL;
    state->bar_state->xpmem_read_cmd_hcall_id  = XPMEM_READ_CMD_HCALL;

    /* Setup other bar information */
    state->bar_state->xpmem_cmd_size = 0;
    state->bar_state->irq_handled    = 0;

    /* Register hypercall callbacks with Palacios */
    v3_register_hypercall(vm, XPMEM_HCALL, xpmem_hcall, state);
    v3_register_hypercall(vm, XPMEM_IRQ_CLEAR_HCALL, xpmem_irq_clear_hcall, state);
    v3_register_hypercall(vm, XPMEM_READ_CMD_HCALL, xpmem_read_cmd_hcall, state);

    v3_spinlock_init(&(state->lock));
    INIT_LIST_HEAD(&(state->cmd_list));

    // Initialize guest memory map
    // init_xpmem_mem_map(state);

    // Initialize host channel
    state->host_handle = v3_xpmem_host_connect(vm, state);
    if (!state->host_handle) {
        PrintError("Could not initialized XPMEM host channel\n");
        V3_Free(state);
        return -1;
    }

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


    V3_Print("v3_xpmem_command: shooting command into the guest\n");

    iter = (struct xpmem_cmd_ex_iter *)V3_Malloc(sizeof(struct xpmem_cmd_ex_iter));
    if (!iter) {
	PrintError("XPMEM: out of memory\n");
	return -1;
    }

    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
	pfn_len = cmd->attach.num_pfns * sizeof(uint64_t);
    }

    /* Remember command size */
    iter->cmd_size = sizeof(struct xpmem_cmd_ex) + pfn_len;

    iter->cmd = V3_Malloc(iter->cmd_size);
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
        
        /* Update shadow map for the new host PFNs */
	/*
	guest_start_addr = xpmem_add_shadow_map(
	    v3_xpmem,
	    cmd->attach.pfns,
	    cmd->attach.num_pfns);
	*/

        if (guest_start_addr == 0) {
            PrintError("XPMEM: cannot update guest shadow map\n");
	    V3_Free(iter->cmd);
	    V3_Free(iter);
            return -1;
        }

        {
            int i = 0;

            for (i = 0; i < cmd->attach.num_pfns; i++) {
                uint64_t host_pfn    = cmd->attach.pfns[i];;
                addr_t   host_paddr  = (addr_t)(host_pfn << 12);
                addr_t   guest_paddr = guest_start_addr + (i * PAGE_SIZE);

		iter->cmd->attach.pfns[i] = (uint64_t)(guest_paddr >> 12);

                PrintDebug("Host PFN %llu ---> Guest PFN %llu (%p -> %p)\n",
                    (unsigned long long)host_pfn,
                    (unsigned long long)iter->cmd->attach.pfns[i],
                    (void *)host_paddr,
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
