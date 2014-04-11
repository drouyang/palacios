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
#include <devices/lnx_virtio_pci.h>
#include <devices/xpmem.h>


#if V3_CONFIG_DEBUG_XPMEM == 1
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEV_ID        0x100d
#define XPMEM_SUBDEVICE_ID  13

#define INT_REQUEST             0x01
#define INT_COMPLETE		    0x02

#define GUEST_DEFAULT_BAR       0xe0000000


struct xpmem_hypercall_info {
    uint32_t make_hcall;
    uint32_t remove_hcall;
    uint32_t get_hcall;
    uint32_t release_hcall;
    uint32_t attach_hcall;
    uint32_t detach_hcall;
    uint32_t command_complete_hcall;
};


struct xpmem_cmd_iter {
    struct list_head node;
    struct xpmem_cmd_ex * cmd;
};


struct xpmem_bar_state {
    /* Hypercall numbers */
    struct xpmem_hypercall_info hcall_info;

    /* Interrupt status */
    uint8_t interrupt_status;

    /* Incoming command request */
    struct xpmem_cmd_ex request;

    /* Incoming response to a previously issued command */
    struct xpmem_cmd_ex response;
};


struct xpmem_mem_iter {
    addr_t guest_start;
    addr_t guest_end;
    struct list_head node;
};


struct v3_xpmem_state {
    struct v3_vm_info * vm;
    struct vm_device * pci_bus;
    struct pci_device * pci_dev;

    struct v3_core_info * core;

    /* Handle to host state */
    xpmem_host_handle_t host_handle;

    /* List of pending incoming commands */
    struct list_head xpmem_cmd_list;
    v3_spinlock_t xpmem_cmd_lock;

    /* Interrupt status lock */
    v3_spinlock_t interrupt_lock;

    /* Bar exposed to guest */
    struct xpmem_bar_state * bar_state;

    /* GPA of a buffer for storing the vPFNs mapping the result of a local outgoing attach request */
    addr_t local_pfn_gpa;

    /* GPA of a buffer for storing the vPFNs mapping the result of a remote incoming attach request */
    addr_t remote_pfn_gpa;

    /* Guest XPMEM memory map */
    struct list_head mem_map;
};


static int xpmem_free(void * private_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)private_data;

    V3_Free(state);

    return 0;
}

static struct v3_device_ops dev_ops = {
    .free = xpmem_free,
};



static int irq_ack(struct v3_core_info * core, uint32_t irq, void * private_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)private_data;
    struct pci_device * pci_dev = state->pci_dev;
    struct vm_device * pci_bus = state->pci_bus;

    v3_pci_lower_irq(pci_bus, pci_dev, pci_dev->config_header.intr_line);

    return 0;
}

static int xpmem_raise_irq(struct v3_xpmem_state * v3_xpmem) {
    struct pci_device * pci_dev = v3_xpmem->pci_dev;
    struct vm_device * pci_bus = v3_xpmem->pci_bus;
    struct v3_irq vec;

    if (pci_dev->irq_type == IRQ_NONE) {
        PrintError("No IRQ type set\n");
        return -1;
    } else if (pci_dev->irq_type == IRQ_INTX) { 
        vec.irq = pci_dev->config_header.intr_line;
        vec.ack = irq_ack;
        vec.private_data = v3_xpmem;

        v3_pci_raise_acked_irq(pci_bus, pci_dev, vec);
    } else {
        v3_pci_raise_irq(pci_bus, pci_dev, 0); 
    }   

    return 0;
}

static int copy_guest_regs(struct v3_xpmem_state * state, struct v3_core_info * core, struct xpmem_cmd_ex * cmd) {
    unsigned long flags;
    int ret = 0;

    flags = v3_spin_lock_irqsave(state->interrupt_lock);

    switch (cmd->type) {
        case XPMEM_MAKE:
            cmd->make.segid = core->vm_regs.rbx;
            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_REMOVE:
            cmd->remove.segid = core->vm_regs.rbx;
            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_GET:
            cmd->get.segid = core->vm_regs.rbx;
            cmd->get.flags = core->vm_regs.rcx;
            cmd->get.permit_type = core->vm_regs.rdx;
            cmd->get.permit_value = core->vm_regs.rsi;
            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_RELEASE:
            cmd->release.apid = core->vm_regs.rbx;
            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_ATTACH:
            cmd->attach.apid = core->vm_regs.rbx;
            cmd->attach.off = core->vm_regs.rcx;
            cmd->attach.size = core->vm_regs.rdx;

            /* Copy GVA and core into state */
            state->local_pfn_gpa = core->vm_regs.rsi;
            state->core = core;

            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_DETACH:
            cmd->detach.vaddr = core->vm_regs.rbx;
            state->bar_state->interrupt_status &= ~INT_COMPLETE;
            break;

        case XPMEM_GET_COMPLETE:
            cmd->get.apid = core->vm_regs.rbx;
            break;

        case XPMEM_RELEASE_COMPLETE:
            break;

        case XPMEM_ATTACH_COMPLETE:
            /* Copy GVA and core into state */
            state->remote_pfn_gpa = core->vm_regs.rbx;
            break;

        case XPMEM_DETACH_COMPLETE:
            break;

        default:
            // What is this?
            ret = -1;
            break;
    }

    v3_spin_unlock_irqrestore(state->interrupt_lock, flags);
    return ret;
}

static int make_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_MAKE;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int remove_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_REMOVE;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int get_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_GET;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int release_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_RELEASE;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int attach_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_ATTACH;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int detach_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    memset(cmd, 0, sizeof(struct xpmem_cmd_ex));
    cmd->type = XPMEM_DETACH;

    if (copy_guest_regs(state, core, cmd)) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static void set_complete(struct xpmem_cmd_ex * cmd) {
    switch(cmd->type) {
        case XPMEM_GET:
            cmd->type = XPMEM_GET_COMPLETE;
            break;

        case XPMEM_RELEASE:
            cmd->type = XPMEM_RELEASE_COMPLETE;
            break;

        case XPMEM_ATTACH:
            cmd->type = XPMEM_ATTACH_COMPLETE;
            break;

        case XPMEM_DETACH:
            cmd->type = XPMEM_DETACH_COMPLETE;
            break;

        default:
            break;
    }
}


static int command_complete_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) {
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)priv_data;
    struct xpmem_cmd_ex * cmd = V3_Malloc(sizeof(struct xpmem_cmd_ex));
    struct xpmem_cmd_iter * iter = NULL;
    unsigned long flags, interrupt_flags;

    if (!cmd) {
        PrintError("XPMEM failed to allocate memory for guest hypercall structure\n");
        return -1;
    }

    /* The type of the command completion can be pulled directly from the
     * request structure, as the guest is required to process requests one at a
     * time in the order that they arrive
     */
    set_complete(&(state->bar_state->request));

    if (copy_guest_regs(state, core, &(state->bar_state->request))) {
        PrintError("Failed to copy guest registers\n");
        return -1;
    }

    /* We still need to copy the request into a separate struct however, as it
     * may buffer in the host for some time
     */
    *cmd = state->bar_state->request;

    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
        /* Copy the attachment list pfns from the guest */
        uint64_t i = 0;
        addr_t host_buf_addr;
        addr_t guest_buf_addr = state->remote_pfn_gpa;
        cmd->attach.num_pfns = cmd->attach.size / PAGE_SIZE;

        if (v3_gpa_to_hva(core, guest_buf_addr, &(host_buf_addr))) {
            PrintError("Unable to convert GPA %p to HVA\n", (void *)guest_buf_addr);
            return -1;
        }

        cmd->attach.pfns = V3_Malloc(sizeof(uint64_t) * cmd->attach.num_pfns);
        if (!cmd->attach.pfns) {
            PrintError("Cannot generate PFN list: out of memory\n");
            return -1;
        }

        /* Now, host_buf_addr points to the guest page frame list */
        for (i = 0;  i < cmd->attach.num_pfns; i++) {
            uint64_t guest_pfn = *((uint64_t *)(host_buf_addr + (i * sizeof(uint64_t))));
            uint64_t host_pfn;
            addr_t guest_paddr;
            addr_t host_paddr;

            guest_paddr = (addr_t)(guest_pfn << 12);

            if (v3_gpa_to_hpa(core, guest_paddr, &(host_paddr))) {
                PrintError("Unable to convert GPA %p to HPA\n", (void *)guest_pfn);
                return -1;
            }

            host_pfn = (uint64_t)(host_paddr >> 12);

            V3_Print("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
		(unsigned long long)guest_pfn,
		(unsigned long long)host_pfn,
		(void *)guest_paddr,
		(void *)host_paddr
	    );

            cmd->attach.pfns[i] = (uint64_t)host_pfn;
        }
    }

    interrupt_flags = v3_spin_lock_irqsave(state->interrupt_lock);
    flags = v3_spin_lock_irqsave(state->xpmem_cmd_lock);

    if (list_empty(&(state->xpmem_cmd_list))) {
        v3_spin_unlock_irqrestore(state->xpmem_cmd_lock, flags);
        state->bar_state->interrupt_status &= ~INT_REQUEST;
        v3_spin_unlock_irqrestore(state->interrupt_lock, interrupt_flags);
    } else {
        iter = list_first_entry(&(state->xpmem_cmd_list), struct xpmem_cmd_iter, node);
        list_del(&(iter->node));
        v3_spin_unlock_irqrestore(state->xpmem_cmd_lock, flags);

        state->bar_state->request = *(iter->cmd);
        state->bar_state->interrupt_status |= INT_REQUEST;
        xpmem_raise_irq(state);

        V3_Free(iter->cmd);
        V3_Free(iter);

        v3_spin_unlock_irqrestore(state->interrupt_lock, interrupt_flags);
    }

    return v3_xpmem_host_command(state->host_handle, cmd);
}

static int register_xpmem_dev(struct v3_xpmem_state * state) {
    struct v3_pci_bar bars[6];
    struct pci_device * pci_dev = NULL;
    int i = 0;

    if (state->pci_bus == NULL) {
        PrintError("XPMEM: Not attached to any PCI bus!\n");
        return -1;
    }

    for (i = 0; i < 6; i++) {
        bars[i].type = PCI_BAR_NONE;
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

    pci_dev->config_header.vendor_id = XPMEM_VENDOR_ID;
    pci_dev->config_header.subsystem_vendor_id = XPMEM_SUBVENDOR_ID;

    pci_dev->config_header.device_id = XPMEM_DEV_ID;
    pci_dev->config_header.class = PCI_CLASS_MEMORY;
    pci_dev->config_header.subclass = PCI_MEM_SUBCLASS_OTHER;
    pci_dev->config_header.subsystem_id = XPMEM_SUBDEVICE_ID;

    pci_dev->config_header.intr_pin = 1; 

    state->pci_dev = pci_dev;

    return 0;
}


#define XPMEM_MEM_INCR 0x40000000LL
#define XPMEM_MEM_SIZE 0x400000000LL
#define XPMEM_MAX_ADDR 0x2000000000LL

static int init_xpmem_mem_map(struct v3_xpmem_state * state) {
    INIT_LIST_HEAD(&(state->mem_map));
    addr_t try_addr = 0;

    for (try_addr = 0; try_addr < XPMEM_MAX_ADDR; try_addr += XPMEM_MEM_INCR) {
        if (!v3_add_shadow_mem(state->vm, 
                    V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
                    try_addr,
                    try_addr + XPMEM_MEM_SIZE,
                    0)) {
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

        if (v3_add_shadow_mem(state->vm, V3_MEM_CORE_ANY, V3_MEM_RD | V3_MEM_WR,
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

static int xpmem_init(struct v3_vm_info * vm, v3_cfg_tree_t * cfg){
    struct vm_device * pci_bus = v3_find_dev(vm, v3_cfg_val(cfg, "bus"));
    char * dev_id = v3_cfg_val(cfg, "ID");
    struct v3_xpmem_state * state = (struct v3_xpmem_state *)V3_Malloc(sizeof(struct v3_xpmem_state));
    addr_t bar_pa;

    if (state == NULL) {
        PrintError("Cannot allocate state for xpmem device\n");
        return -1;
    }

    memset(state, 0, sizeof(struct v3_xpmem_state));
    state->pci_bus = pci_bus;
    state->vm = vm;

    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, state);

    if (dev == NULL) {
        PrintError("Could not attach device %s\n", dev_id);
        V3_Free(state);
        return -1;
    }

    bar_pa = (addr_t)V3_AllocPages(1);
    state->bar_state = V3_VAddr((void *)bar_pa);

    if (v3_add_shadow_mem(state->vm, V3_MEM_CORE_ANY, V3_MEM_RD,
                GUEST_DEFAULT_BAR,
                GUEST_DEFAULT_BAR + PAGE_SIZE,
                bar_pa)) {
        PrintError("Failed to add XPMEM shadow BAR region\n");
    }

    state->bar_state->hcall_info.make_hcall = XPMEM_MAKE_HCALL;
    state->bar_state->hcall_info.remove_hcall = XPMEM_REMOVE_HCALL;
    state->bar_state->hcall_info.get_hcall = XPMEM_GET_HCALL;
    state->bar_state->hcall_info.release_hcall = XPMEM_RELEASE_HCALL;
    state->bar_state->hcall_info.attach_hcall = XPMEM_ATTACH_HCALL;
    state->bar_state->hcall_info.detach_hcall = XPMEM_DETACH_HCALL;
    state->bar_state->hcall_info.command_complete_hcall = XPMEM_CMD_COMPLETE_HCALL;

    v3_register_hypercall(vm, XPMEM_MAKE_HCALL, make_hcall, state);
    v3_register_hypercall(vm, XPMEM_REMOVE_HCALL, remove_hcall, state);
    v3_register_hypercall(vm, XPMEM_GET_HCALL, get_hcall, state);
    v3_register_hypercall(vm, XPMEM_RELEASE_HCALL, release_hcall, state);
    v3_register_hypercall(vm, XPMEM_ATTACH_HCALL, attach_hcall, state);
    v3_register_hypercall(vm, XPMEM_DETACH_HCALL, detach_hcall, state);
    v3_register_hypercall(vm, XPMEM_CMD_COMPLETE_HCALL, command_complete_hcall, state);

    INIT_LIST_HEAD(&(state->xpmem_cmd_list));
    v3_spinlock_init(&(state->xpmem_cmd_lock));

    state->bar_state->interrupt_status = 0;
    v3_spinlock_init(&(state->interrupt_lock));

    // Initialize guest memory map
    init_xpmem_mem_map(state);

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


/* Incoming XPMEM commands
 * Can be either:
 *      XPMEM_GET       - remote process requesting an apid
 *      XPMEM_RELEASE   - remote process releasing an apid
 *      XPMEM_ATTACH    - remote process attaching to an apid
 *      XPMEM_DETACH    - remote process detaching from an apid
 */
static int xpmem_command_request(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd_ex * cmd) {
    struct xpmem_cmd_iter * iter = NULL;
    unsigned long flags, interrupt_flags;
    int ret = 0;

    interrupt_flags = v3_spin_lock_irqsave(v3_xpmem->interrupt_lock);
    flags = v3_spin_lock_irqsave(v3_xpmem->xpmem_cmd_lock);

    if (list_empty(&(v3_xpmem->xpmem_cmd_list))) {
        v3_xpmem->bar_state->request = *cmd;
        v3_xpmem->bar_state->interrupt_status |= INT_REQUEST;
        ret = xpmem_raise_irq(v3_xpmem);

        V3_Free(cmd);
    } else {
        iter = V3_Malloc(sizeof(struct xpmem_cmd_iter));

        if (!iter) {
            PrintError("Cannot append xpmem command list: out of memory\n");
            return -1;
        }

        iter->cmd = cmd;
        list_add_tail(&(iter->node), &(v3_xpmem->xpmem_cmd_list));
    }

    v3_spin_unlock_irqrestore(v3_xpmem->xpmem_cmd_lock, flags);
    v3_spin_unlock_irqrestore(v3_xpmem->interrupt_lock, interrupt_flags);

    return ret;
}

/* Incoming response to a previously issued XPMEM command
 * Can be either:
 *      XPMEM_MAKE_COMPLETE     - response to an XPMEM make
 *      XPMEM_REMOVE_COMPLETE   - response to an XPMEM remove
 *      XPMEM_GET_COMPLETE      - response to an XPMEM get
 *      XPMEM_RELEASE_COMPLETE  - response to an XPMEM release
 *      XPMEM_ATTACH_COMPLETE   - response to an XPMEM attach
 *      XPMEM_DETACH_COMPLETE   - response to an XPMEM detach
 */

/* We can write directly to the BAR - there is only ever a single outgoing
 * request at a time, so we can always write the response directly in
 */
static int xpmem_command_complete(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd_ex * cmd) {
    unsigned long interrupt_flags;

    if ((cmd->type == XPMEM_ATTACH_COMPLETE) && (cmd->attach.num_pfns > 0)) {
        addr_t guest_start_addr = 0;
        
        /* Add new shadow map for the PFNs */
        if ((guest_start_addr = xpmem_add_shadow_map(v3_xpmem, cmd->attach.pfns, cmd->attach.num_pfns)) == 0) {
            PrintError("XPMEM: Unable to complete remote XPMEM attachment: cannot update shadow map\n");
            return -1;
        }

        /* Copy the attachment list pfns into the guest */
        {
            uint64_t i = 0;
            addr_t host_buf_addr;
            addr_t guest_buf_addr = v3_xpmem->local_pfn_gpa;

            if (v3_gpa_to_hva(v3_xpmem->core, guest_buf_addr, &(host_buf_addr))) {
                PrintError("Unable to convert GPA %p to HVA\n", (void *)guest_buf_addr);
                return -1;
            }

            /* Now, host_buf_addr points to the guest page frame list */
            for (i = 0; i < cmd->attach.num_pfns; i++) {
                uint64_t guest_pfn;
                uint64_t host_pfn;
                addr_t guest_paddr;
                addr_t guest_buf;

                guest_paddr = guest_start_addr + (i * PAGE_SIZE);
                guest_pfn = (uint64_t)(guest_paddr >> 12);
                host_pfn = cmd->attach.pfns[i];

                V3_Print("Guest PFN %llu ---> Host PFN %llu (%p -> %p)\n",
                        (unsigned long long)guest_pfn,
                        (unsigned long long)host_pfn,
                        (void *)guest_paddr,
                        (void *)(host_pfn << 12)
                );

                guest_buf = host_buf_addr + (i * sizeof(uint64_t));
                *((uint64_t *)guest_buf) = guest_pfn;
            }

            V3_Free(cmd->attach.pfns);
        }
    }

    interrupt_flags = v3_spin_lock_irqsave(v3_xpmem->interrupt_lock);
    v3_xpmem->bar_state->interrupt_status |= INT_COMPLETE;
    v3_spin_unlock_irqrestore(v3_xpmem->interrupt_lock, interrupt_flags);

    v3_xpmem->bar_state->response = *cmd;
    V3_Free(cmd);

    return xpmem_raise_irq(v3_xpmem);
}

int v3_xpmem_command(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd_ex * cmd) {
    switch (cmd->type) {
        case XPMEM_GET:
        case XPMEM_RELEASE:
        case XPMEM_ATTACH:
        case XPMEM_DETACH:
            return xpmem_command_request(v3_xpmem, cmd);

        case XPMEM_MAKE_COMPLETE:
        case XPMEM_REMOVE_COMPLETE:
        case XPMEM_GET_COMPLETE:
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE:
            return xpmem_command_complete(v3_xpmem, cmd);

        default:
            PrintError("Invalid XPMEM command request/completion (%d)\n", cmd->type);
            return -1;
    }
}


device_register("XPMEM", xpmem_init)
