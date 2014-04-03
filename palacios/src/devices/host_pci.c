/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2012, Jack Lange <jacklange@cs.pitt.edu>
 * Copyright (c) 2012, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


/* This is the generic passthrough PCI virtual device */

/* 
 * The basic idea is that we do not change the hardware PCI configuration
 * Instead we modify the guest environment to map onto the physical configuration
 * 
 * The pci subsystem handles most of the configuration space, except for the bar registers.
 * We handle them here, by either letting them go directly to hardware or remapping through virtual hooks
 * 
 * Memory Bars are always remapped via the shadow map, 
 * IO Bars are selectively remapped through hooks if the guest changes them 
 */

#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <palacios/vmm_sprintf.h>
#include <palacios/vmm_lowlevel.h>
#include <palacios/vm.h> // must include this to avoid dependency issue

#include <devices/pci.h>
#include <devices/pci_types.h>
#include <interfaces/host_pci.h>

#define PCI_BUS_MAX  7
#define PCI_DEV_MAX  32
#define PCI_FN_MAX   7

#define PCI_DEVICE         0x0
#define PCI_PCI_BRIDGE     0x1
#define PCI_CARDBUS_BRIDGE 0x2

#define PCI_HDR_SIZE 256




struct host_pci_state {
    // This holds the description of the host PCI device configuration
    struct v3_host_pci_dev * host_dev;


    struct v3_host_pci_bar virt_bars[6];
    struct v3_host_pci_bar virt_exp_rom;

    struct vm_device  * pci_bus;
    struct pci_device * pci_dev;

    char name[32];

    // MSI-X info
    addr_t   msix_table_pa;
    uint32_t msix_table_num_pages;
    uint16_t msix_table_bir;
    uint32_t msix_table_offset;

    addr_t   msix_pba_pa;
    uint32_t msix_pba_num_pages;
    uint16_t msix_pba_bir;
    uint32_t msix_pba_offset;
};





static int 
pt_io_read(struct v3_core_info * core, 
	   uint16_t              port, 
	   void                * dst, 
	   uint_t                length, 
	   void                * priv_data) 
{
    struct v3_host_pci_bar * pbar        = (struct v3_host_pci_bar *)priv_data;
    int                      port_offset = port % pbar->size;

    if (length == 1) {
        *(uint8_t  *)dst = v3_inb(pbar->addr  + port_offset);
    } else if (length == 2) {
        *(uint16_t *)dst = v3_inw(pbar->addr  + port_offset);
    } else if (length == 4) {
        *(uint32_t *)dst = v3_indw(pbar->addr + port_offset);
    } else {
        PrintError("Invalid PCI passthrough IO Redirection size read\n");
        return -1;
    }

    return length;
}


static int 
pt_io_write(struct v3_core_info * core, 
	    uint16_t              port, 
	    void                * src, 
	    uint_t                length, 
	    void                * priv_data) 
{
    struct v3_host_pci_bar * pbar        = (struct v3_host_pci_bar *)priv_data;
    int                      port_offset = port % pbar->size;

    if (length == 1) {
        v3_outb(pbar->addr  + port_offset, *(uint8_t  *)src);
    } else if (length == 2) {
        v3_outw(pbar->addr  + port_offset, *(uint16_t *)src);
    } else if (length == 4) {
        v3_outdw(pbar->addr + port_offset, *(uint32_t *)src);
    } else {
        PrintError("Invalid PCI passthrough IO Redirection size write\n");
        return -1;
    }

    return length;

}

static int 
remap_shadow_region(struct vm_device       * dev,
		    struct v3_host_pci_bar * old_vbar, 
		    struct v3_host_pci_bar * new_vbar, 
		    struct v3_host_pci_bar * hbar, 
		    uint32_t                 bar_number) 
{

    struct host_pci_state  * state     = (struct host_pci_state *)dev->private_data;
    //  struct v3_host_pci_bar * hbar      = &(state->host_dev->bars[bar_number]);
    uint32_t                 mem_flags = V3_MEM_RD | V3_MEM_WR;
    int                      status    = 0;

    new_vbar->is_mapped = 0;
    
    if (!hbar->cacheable) {
        mem_flags |= V3_MEM_UC;
    }

    PrintDebug("Remapping bar number %d (msi-x bar number %d)\n", 
	       bar_number, state->msix_table_bir);

    if (bar_number != state->msix_table_bir) {
        if ( (old_vbar) && 
	     (old_vbar->is_mapped) ) {
            // remove old mapping
            struct v3_mem_region * old_reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, old_vbar->addr);

            if (old_reg == NULL) {
                // uh oh...
                PrintError("Could not find PCI Passthrough memory redirection region (addr=0x%x)\n", (uint32_t)old_vbar->addr);
                return -1;
            }

            v3_delete_mem_region(dev->vm, old_reg);
        }

        status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
				   mem_flags, 
				   new_vbar->addr, 
				   new_vbar->addr + new_vbar->size - 1,
				   hbar->addr);

        if (status == 0) {
            new_vbar->is_mapped = 1;
        }
    } else {
        /* MSI-X bar */

        addr_t first_region_start   = 0;
        addr_t msix_table_start     = 0;
        addr_t last_region_start    = 0;
        addr_t bar_start            = 0;
        addr_t bar_end              = 0;

        uint_t first_region_present = 0;
        uint_t last_region_present  = 0;

        if (old_vbar && old_vbar->is_mapped) {
            /* Delete the BAR */
            first_region_start = old_vbar->addr;
            msix_table_start   = old_vbar->addr + state->msix_table_offset;
            last_region_start  = msix_table_start + (state->msix_table_num_pages * 4096);
            bar_start          = old_vbar->addr;
            bar_end            = old_vbar->addr + old_vbar->size;

            if (msix_table_start > first_region_start) {
                first_region_present = 1;
            }

            if (last_region_start < bar_end) {
                last_region_present  = 1;
            }

            PrintDebug("Removing MSI-X bar:\n"
		       "\tFirst region: %p - %p (present: %d)\n"
		       "\tMSI-X tablen: %p - %p\n"
		       "\tLast region:  %p - %p (present: %d)\n"
		       "\tOld bar mapped: %d\n",
		       (void *)first_region_start, 
		       (void *)msix_table_start, 
		       first_region_present,
		       (void *)msix_table_start, 
		       (void *)last_region_start,
		       (void *)last_region_start, 
		       (void *)bar_end, 
		       last_region_present,
		       (old_vbar) ? old_vbar->is_mapped : 0);
            
	    /* Remove mapping before the MSI-X region */ 
	    if (first_region_present) {
                struct v3_mem_region * old_reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, first_region_start);
		
                if (old_reg == NULL) {
                    // uh oh...
                    PrintError("Could not find PCI Passthrough memory redirection region (addr=0x%x)\n", (uint32_t)first_region_start);
                    return -1;
                }
		
                v3_delete_mem_region(dev->vm, old_reg);
            }
	    
	    /* remove old MSI-X mapping */
            {
                struct v3_mem_region * old_reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, msix_table_start);

                if (old_reg == NULL) {
                    // uh oh...
                    PrintError("Could not find PCI Passthrough memory redirection region (addr=0x%x)\n", (uint32_t)msix_table_start);
                    return -1;
                }

                v3_delete_mem_region(dev->vm, old_reg);
            }

	    /* Remove Mapping after the MSI-X region */
            if (last_region_present) {
                struct v3_mem_region * old_reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, last_region_start);

                if (old_reg == NULL) {
                    // uh oh...
                    PrintError("Could not find PCI Passthrough memory redirection region (addr=0x%x)\n", (uint32_t)last_region_start);
                    return -1;
                }

                v3_delete_mem_region(dev->vm, old_reg);
            }

            old_vbar->is_mapped = 0;
        }

        /*
	 * Remap BAR 
	 */
        first_region_start = new_vbar->addr;
        msix_table_start   = new_vbar->addr + state->msix_table_offset;
        last_region_start  = msix_table_start + (state->msix_table_num_pages * 4096);
        bar_start          = new_vbar->addr;
        bar_end            = new_vbar->addr + new_vbar->size;

        if (msix_table_start > first_region_start) {
            first_region_present = 1;
        }

        if (last_region_start < bar_end) {
            last_region_present  = 1;
        }

        // Check overlap
        {
            status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY,
				       mem_flags,
				       bar_start,
				       bar_end,
				       hbar->addr);

            if (status != 0) {
                PrintError("Cannot map MSI-X bar - overlapping memory region present\n");
                return -1;
            }

            { 
                struct v3_mem_region * reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, bar_start);
                v3_delete_mem_region(dev->vm, reg);
            }
        }

        PrintDebug("Mapping MSI-X bar:\n"
		   "\tFirst region: %p - %p (present: %d)\n"
		   "\tMSI-X tablen: %p - %p\n"
		   "\tLast region:  %p - %p (present: %d)\n"
		   "\tOld bar mapped: %d\n",
		   (void *)first_region_start, 
		   (void *)msix_table_start, 
		   first_region_present,
		   (void *)msix_table_start, 
		   (void *)last_region_start,
		   (void *)last_region_start, 
		   (void *)bar_end, 
		   last_region_present,
		   (old_vbar) ? old_vbar->is_mapped : 0);

	/* Add mapping for region BEFORE the MSI-X table */
        if (first_region_present) {
            PrintDebug("Adding first shadow mem region: %p -> %p, (host: %p)\n",
		       (void *)first_region_start,
		       (void *)msix_table_start,
		       (void *)hbar->addr);
	    
            status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
				       mem_flags, 
				       first_region_start, 
				       msix_table_start,
				       hbar->addr);
            
            if (status != 0) {
                PrintError("Failed to add shadow mem region: %p -> %p, (host: %p)\n",
			   (void *)first_region_start,
			   (void *)msix_table_start,
			   (void *)hbar->addr);
                return -1;
            }
        }

	/* Map in the MSI-X Table */
        {
            PrintDebug("Adding MSI-X shadow mem region: %p -> %p, (host: %p)\n",
		       (void *)msix_table_start,
		       (void *)last_region_start,
		       (void *)state->msix_table_pa);
	    
            status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
				       mem_flags, 
				       msix_table_start,
				       last_region_start, 
				       state->msix_table_pa);
            
            if (status != 0) {
                PrintError("Failed to add shadow mem region: %p -> %p, (host: %p)\n",
			   (void *)msix_table_start,
			   (void *)last_region_start,
			   (void *)state->msix_table_pa);
                return -1;
            }
        }

	/* Add mapping for region AFTER the MSI-X table */
        if (last_region_present) {
            PrintDebug("Adding last shadow mem region: %p -> %p, (host: %p)\n",
		       (void *)last_region_start,
		       (void *)bar_end,
		       (void *)(hbar->addr + (last_region_start - bar_start)));
	    
            status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
				       mem_flags, 
				       last_region_start, 
				       bar_end,
				       hbar->addr + (last_region_start - bar_start));
            
            if (status != 0) {
                PrintError("Failed to add shadow mem region: %p -> %p, (host: %p)\n",
			   (void *)last_region_start,
			   (void *)bar_end,
			   (void *)(hbar->addr + (last_region_start - bar_start)));
                return -1;
            }
        }

        new_vbar->is_mapped = 1;
    }

    return 0;
}

static int 
pci_exp_rom_init(struct vm_device      * dev, 
		 struct host_pci_state * state) 
{
    struct pci_device      * pci_dev = state->pci_dev;
    struct v3_host_pci_bar * hrom    = &(state->host_dev->exp_rom);
    int                      status  = 0;
    //  struct v3_host_pci_dev * v3_dev  = state->host_dev;

    //PrintDebug("Adding 32 bit PCI mem region: start=%p, end=%p\n",
    //    (void *)(addr_t)hrom->addr, 
    //    (void *)(addr_t)(hrom->addr + hrom->size));
    
    // only map shadow memory if the ROM is enabled 
    //if (hrom->exp_rom_enabled) {

    status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
			       V3_MEM_RD | V3_MEM_WR | V3_MEM_UC, 
			       hrom->addr, 
			       hrom->addr + hrom->size - 1,
			       hrom->addr);


    // Initially the virtual location matches the physical ones
    memcpy(&(state->virt_exp_rom), hrom, sizeof(struct v3_host_pci_bar));

    if (status == 0) {
        state->virt_exp_rom.is_mapped = 1;
    }

    // Update the pci subsystem versions
    pci_dev->config_header.expansion_rom_address = PCI_EXP_ROM_VAL(hrom->addr, hrom->exp_rom_enabled);

    return 0;
}

static int 
pci_bar_init(int        bar_num, 
	     uint32_t * dst, 
	     void     * private_data) 
{
    struct vm_device       * dev     = (struct vm_device *)private_data;
    struct host_pci_state  * state   = (struct host_pci_state *)dev->private_data;
    struct v3_host_pci_bar * hbar    = &(state->host_dev->bars[bar_num]);
    uint32_t                 bar_val = 0;

    V3_Print("%s: pci_bar_init: bar %d type: %d\n",
	     state->name, bar_num, hbar->type);

    if (hbar->type == PT_BAR_IO) {
        int i = 0;

        bar_val = PCI_IO_BAR_VAL(hbar->addr);

        for (i = 0; i < hbar->size; i++) {
            v3_hook_io_port(dev->vm, hbar->addr + i, NULL, NULL, NULL);
        }

    } else if (hbar->type == PT_BAR_MEM32) {

        bar_val = PCI_MEM32_BAR_VAL(hbar->addr, hbar->prefetchable);
        remap_shadow_region(dev, NULL, hbar, hbar, bar_num);

    } else if (hbar->type == PT_BAR_MEM24) {

        bar_val = PCI_MEM24_BAR_VAL(hbar->addr, hbar->prefetchable);
        remap_shadow_region(dev, NULL, hbar, hbar, bar_num);

    } else if (hbar->type == PT_BAR_MEM64_LO) {

        struct v3_host_pci_bar * hi_hbar = &(state->host_dev->bars[bar_num + 1]);
        bar_val = PCI_MEM64_LO_BAR_VAL(hi_hbar->addr, hbar->prefetchable);

    } else if (hbar->type == PT_BAR_MEM64_HI) {

        bar_val = PCI_MEM64_HI_BAR_VAL(hbar->addr >> 32, hbar->prefetchable);
        remap_shadow_region(dev, NULL, hbar, hbar, bar_num - 1);

    } 
    

    memcpy(&(state->virt_bars[bar_num]), hbar, sizeof(struct v3_host_pci_bar));

    *dst = bar_val;

    return 0;
}

static int 
pci_bar_write(int        bar_num, 
	      uint32_t * src, 
	      void     * private_data) 
{
    struct vm_device      * dev   = (struct vm_device *)private_data;
    struct host_pci_state * state = (struct host_pci_state *)dev->private_data;

    struct v3_host_pci_bar * hbar = &(state->host_dev->bars[bar_num]);
    struct v3_host_pci_bar * vbar = &(state->virt_bars[bar_num]);


    V3_Print("%s: pci_bar_write: bar %d type: %d\n",
	     state->name, bar_num, vbar->type);

    V3_Print("vbar->size: %dold addr: %p, new val: %x\n",
	     vbar->size, (void *)vbar->addr, *(src));

    if (vbar->type == PT_BAR_NONE) {
        *src = 0;
        return 0;
    } else if (vbar->type == PT_BAR_IO) {
        int i = 0;

        // unhook old ports
        for (i = 0; i < vbar->size; i++) {
            if (v3_unhook_io_port(dev->vm, vbar->addr + i) == -1) {
                PrintError("Could not unhook previously hooked port.... %d (0x%x)\n", 
			   (uint32_t)vbar->addr + i, (uint32_t)vbar->addr + i);
                return -1;
            }
        }

        vbar->addr = *src & ~(hbar->size - 1);    /* clear the low bits to match the size */
        *src       = PCI_IO_BAR_VAL(vbar->addr);  /* udpate source version                */


        PrintDebug("Rehooking passthrough IO ports starting at %d (0x%x)\n", 
		   (uint32_t)vbar->addr, (uint32_t)vbar->addr);

        if (vbar->addr == hbar->addr) {
            // Map the io ports as passthrough
            for (i = 0; i < hbar->size; i++) {
                v3_hook_io_port(dev->vm, hbar->addr + i, NULL, NULL, NULL); 
            }
        } else {
            // We have to manually handle the io redirection
            for (i = 0; i < vbar->size; i++) {
                v3_hook_io_port(dev->vm, vbar->addr + i, pt_io_read, pt_io_write, hbar); 
            }
        }

    } else if (vbar->type == PT_BAR_MEM32) {
        struct v3_host_pci_bar old_vbar;
     
	old_vbar   = *vbar;
        vbar->addr = *src & ~(hbar->size - 1);                          /* clear the low bits to match the size */
        *src       = PCI_MEM32_BAR_VAL(vbar->addr, hbar->prefetchable); /* Set reserved bits                    */

        PrintDebug("Adding pci Passthrough remapping: start=0x%x, size=%d, end=0x%x (hpa=%p)\n", 
		   (uint32_t)vbar->addr, vbar->size, (uint32_t)vbar->addr + vbar->size, (void *)hbar->addr);

        remap_shadow_region(dev, &old_vbar, vbar, hbar, bar_num);

    } else if (vbar->type == PT_BAR_MEM64_LO) {
        // We only store the written values here, the actual reconfig comes when the high BAR is updated
        struct v3_host_pci_bar * hi_bar = &(state->virt_bars[bar_num + 1]);
        struct v3_host_pci_bar   old_hi_bar;

        old_hi_bar    = *hi_bar;
        vbar->addr    = *src & ~(hbar->size - 1);
        hi_bar->addr &= 0xFFFFFFFF00000000LL;
        hi_bar->addr |= vbar->addr;

        *src          = PCI_MEM64_LO_BAR_VAL(vbar->addr, hbar->prefetchable);

        remap_shadow_region(dev, &old_hi_bar, hi_bar, hbar, bar_num);

    } else if (vbar->type == PT_BAR_MEM64_HI) {
        struct v3_host_pci_bar * lo_vbar = &(state->virt_bars[bar_num - 1]);
        struct v3_host_pci_bar   old_vbar;

        old_vbar   = *vbar;
        vbar->addr = (((uint64_t)*src) << 32) + lo_vbar->addr;

        // We don't set size, because we assume region is less than 4GB
        // src does not change, because there are no reserved bits
        *src       = PCI_MEM64_HI_BAR_VAL(vbar->addr >> 32, hbar->prefetchable);

        PrintDebug("hi_bar Adding pci Passthrough remapping: start=%p, size=%p, end=%p, src=%x\n", 
		   (void *)(addr_t)vbar->addr, 
		   (void *)(addr_t)vbar->size, 
		   (void *)(addr_t)(vbar->addr + vbar->size),
		   *src);

        remap_shadow_region(dev, &old_vbar, vbar, hbar, bar_num - 1);
    } else {
        PrintError("Unhandled Pasthrough PCI Bar type %d\n", vbar->type);
        return -1;
    }

    V3_Print("new val at vbar: %p\n", (void *)vbar->addr);

    return 0;
}


static int 
pt_config_write(struct pci_device * pci_dev, 
		uint32_t            reg_num, 
		void              * src, 
		uint_t              length, 
		void              * private_data) 
{
    struct vm_device      * dev   = (struct vm_device *)private_data;
    struct host_pci_state * state = (struct host_pci_state *)dev->private_data;

    //    V3_Print("Writing host PCI config space update\n");

    // We will mask all operations to the config header itself, 
    // and only allow direct access to the device specific config space
    if (reg_num < 64) {
        return 0;
    }

    return v3_host_pci_config_write(state->host_dev, reg_num, src, length);
}



static int 
pt_config_read(struct pci_device * pci_dev, 
	       uint32_t            reg_num, 
	       void              * dst, 
	       uint_t              length, 
	       void              * private_data) 
{
    struct vm_device      * dev   = (struct vm_device *)private_data;
    struct host_pci_state * state = (struct host_pci_state *)dev->private_data;

    //  V3_Print("Reading host PCI config space update\n");

    return v3_host_pci_config_read(state->host_dev, reg_num, dst, length);
}




/* This is really iffy....
 * It was totally broken before, but it's _not_ totally fixed now
 * The Expansion rom can be enabled/disabled via software using the low order bit
 * We should probably handle that somehow here... 
 */
static int 
pt_exp_rom_write(struct pci_device * pci_dev, 
		 uint32_t          * src, 
		 void              * priv_data) 
{
    struct vm_device      * dev   = (struct vm_device *)(priv_data);
    struct host_pci_state * state = (struct host_pci_state *)dev->private_data;

    struct v3_host_pci_bar * hrom = &(state->host_dev->exp_rom);
    struct v3_host_pci_bar * vrom = &(state->virt_exp_rom);

    int status = 0;

    PrintDebug("exp_rom update: src=0x%x\n",   *src);
    PrintDebug("vrom is size=%u, addr=0x%x\n", vrom->size, (uint32_t)vrom->addr);
    PrintDebug("hrom is size=%u, addr=0x%x\n", hrom->size, (uint32_t)hrom->addr);


    

    //    if (hrom->exp_rom_enabled) {
    // only remove old mapping if present, I.E. if the rom was enabled previously 
    if (vrom->is_mapped) {
	struct v3_mem_region * old_reg = v3_get_mem_region(dev->vm, V3_MEM_CORE_ANY, vrom->addr);

	if (old_reg == NULL) {
	    // uh oh...
	    PrintError("Could not find PCI Passthrough exp_rom_base redirection region (addr=0x%x)\n", (uint32_t)vrom->addr);
	    return -1;
	}

	v3_delete_mem_region(dev->vm, old_reg);
	vrom->is_mapped = 0;
    }


    vrom->addr = *src & ~(hrom->size - 1);

    // Set flags in actual register value
    *src       = PCI_EXP_ROM_VAL(vrom->addr, (*src & 0x00000001));

    PrintDebug("Cooked src=0x%x\n", *src);


    PrintDebug("Adding pci Passthrough exp_rom_base remapping: start=0x%x, size=%u, end=0x%x\n", 
	     (uint32_t)vrom->addr, vrom->size, (uint32_t)vrom->addr + vrom->size);

    status = v3_add_shadow_mem(dev->vm, V3_MEM_CORE_ANY, 
			       V3_MEM_RD | V3_MEM_WR | V3_MEM_UC | V3_MEM_EXEC, 
			       vrom->addr, 
			       vrom->addr + vrom->size - 1, 
			       hrom->addr);

    if (status == -1) {
	PrintError("Failed to remap pci exp_rom: start=0x%x, size=%u, end=0x%x\n", 
		   (uint32_t)vrom->addr, vrom->size, (uint32_t)vrom->addr + vrom->size);
	return -1;
    }

    vrom->is_mapped = 1;

    return 0;
}


static int 
pt_cmd_update(struct pci_device * pci, 
	      pci_cmd_t           cmd, 
	      uint64_t            arg, 
	      void              * priv_data) 
{
    struct vm_device      * dev         = (struct vm_device *)(priv_data);
    struct host_pci_state * state       = (struct host_pci_state *)dev->private_data;
    int                     max_entries = arg;

    PrintDebug("Host PCI Device: CMD update (%d)(arg=%llu)\n", cmd, arg);

    if (cmd == PCI_CMD_MSIX_ENABLE) {
        // Figure out how many MSIX entries to enable
        struct msix_table * table = (struct msix_table *)V3_VAddr((void *)state->msix_table_pa);

        int i = 0;
        arg   = 0;

        PrintDebug("MSIX_TABLE:\n");
        for (i = 0; i < max_entries; i++) {
            if (table->entries[i].data.val != 0x0) {
                arg++;
            }

            PrintDebug("%x %x %x %x\n",
		        table->entries[i].vector_control,
		        table->entries[i].data.val,
		        table->entries[i].hi_addr,
		        table->entries[i].addr.val
		    );

        }
    }

    v3_host_pci_cmd_update(state->host_dev, cmd, arg);

#if 0
    {
        struct msix_table * table = NULL;
        int i = 0;

	table = (struct msix_table *)ioremap_nocache(state->host_dev->bars[1].addr + 0x7c000, 4096);

        V3_Print("Host MSI-X table address: %p (pa: %p)\n",
		 table, (void *)(state->host_dev->bars[1].addr + 0x7c000));


        V3_Print("max entries: %d\n", max_entries);

        for (i = 0; i < max_entries; i++) {
            V3_Print("entry[%d]: %x %x %x %x\n",
		     i,
		     ioread32((void *)&table->entries[i].vector_control),
		     ioread32((void *)&table->entries[i].data.val),
		     ioread32((void *)&table->entries[i].hi_addr),
		     ioread32((void *)&table->entries[i].addr.val)
		     );

            //iowrite32(0x1, (void *)&table->entries[i].vector_control);
        }
    }
#endif
    return 0;
}


static int 
init_msix_table(struct vm_device * dev, 
		uint32_t           cap_offset) 
{
//    struct vm_device * dev = (struct vm_device *)pci_dev->priv_data;
    struct host_pci_state  * state  = (struct host_pci_state *)dev->private_data;
    struct v3_host_pci_dev * v3_dev = state->host_dev;
    struct msix_cap        * cap    = (struct msix_cap *)&(v3_dev->cfg_space[cap_offset + 2]);

    state->msix_table_bir       = cap->table_bir;
    state->msix_table_offset    = (cap->table_offset) << 3;
    state->msix_table_num_pages = (((cap->msg_ctrl.table_size + 1) * 16) / 4096);

    if (((cap->msg_ctrl.table_size + 1) * 16) % 4096 != 0) {
        state->msix_table_num_pages++;
    }

    state->msix_table_pa = (addr_t)V3_AllocPages(state->msix_table_num_pages);
    memset(V3_VAddr((void *)state->msix_table_pa), 0, state->msix_table_num_pages * 4096);

    V3_Print("Init'ed msi-x table:\n"
	     "  table bir       : %d\n"
	     "  table offset    : %d\n"
	     "  table pa        : %p\n"
	     "  table num pages : %d\n",
	     state->msix_table_bir,
	     state->msix_table_offset,
	     (void *)state->msix_table_pa,
	     state->msix_table_num_pages
	     );


    return 0;
}


static int 
setup_virt_pci_dev(struct v3_vm_info * vm_info, 
		   struct vm_device  * dev)
{
    struct host_pci_state * state   = (struct host_pci_state *)dev->private_data;
    struct pci_device     * pci_dev = NULL;
    struct v3_pci_bar       bars[6];
    int                     bus_num = 0;
    int i = 0;

    for (i = 0; i < 6; i++) {
        bars[i].type         = PCI_BAR_PASSTHROUGH;
        bars[i].private_data = dev;
        bars[i].bar_init     = pci_bar_init;
        bars[i].bar_write    = pci_bar_write;
    }


    // Initially disable MSIX by setting an invalid BAR index
    state->msix_table_bir = -1;

    {
        struct v3_host_pci_dev * v3_dev     = state->host_dev;
        uint_t                   cap_offset = v3_dev->cfg_space[52];

        V3_Print("Enabling Host device Capabilities (cap_offset=%d)\n", cap_offset);

        while (cap_offset != 0) { 
            uint8_t id   = v3_dev->cfg_space[cap_offset];
            uint8_t next = v3_dev->cfg_space[cap_offset + 1];

            V3_Print("Found Capability 0x%x at offset %d (0x%x)\n", 
                    id, cap_offset, cap_offset);

            /*
            switch (id) {
                case PCI_CAP_MSI:
                    v3_pci_enable_capability(pci_dev, PCI_CAP_MSI);
                    break;
                case PCI_CAP_MSIX:
                    init_msix_table(pci_dev, cap_offset);
                    v3_pci_enable_capability(pci_dev, PCI_CAP_MSIX);
                    break;
                case PCI_CAP_PCIE:
                    v3_pci_enable_capability(pci_dev, PCI_CAP_PCIE);
                    break;
                case PCI_CAP_PM:
                    v3_pci_enable_capability(pci_dev, PCI_CAP_PM);
                    break;
                default:
                    break;

            }
            */

            if (id == PCI_CAP_MSIX) {
                init_msix_table(dev, cap_offset);
            }

            // set to the next pointer
            cap_offset = next;
        }    

    }

    pci_dev = v3_pci_register_device(state->pci_bus,
				     PCI_STD_DEVICE,
				     bus_num, -1, 0, 
				     state->name, bars,
				     pt_config_write,
				     pt_config_read,
				     pt_cmd_update,
				     pt_exp_rom_write,               
				     dev);


    state->pci_dev = pci_dev;

    pci_exp_rom_init(dev, state);
    //pci_dev->config_header.expansion_rom_address = 0;

    v3_pci_enable_capability(pci_dev, PCI_CAP_MSI);
    v3_pci_enable_capability(pci_dev, PCI_CAP_MSIX);
    v3_pci_enable_capability(pci_dev, PCI_CAP_PCIE);
    v3_pci_enable_capability(pci_dev, PCI_CAP_PM);
    v3_pci_enable_capability(pci_dev, PCI_CAP_VPD);


    return 0;
}


static int 
host_dev_free(struct host_pci_state * state) 
{
    v3_host_pci_release_dev(state->host_dev);
    V3_Free(state);

    return 0;
}

static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))host_dev_free,
};


static int 
irq_ack(struct v3_core_info * core, 
	uint32_t              irq, 
	void                * private_data) 
{
    struct host_pci_state * state = (struct host_pci_state *)private_data;

    v3_pci_lower_irq(state->pci_bus, state->pci_dev, 0);

    //    V3_Print("Acking IRQ %d\n", irq);
    v3_host_pci_ack_irq(state->host_dev, irq);

    return 0;
}


static int 
irq_handler(void     * private_data, 
	    uint32_t   vec_index) 
{
    struct host_pci_state * state = (struct host_pci_state *)private_data;
    struct v3_irq           vec;

    vec.irq          = vec_index;
    vec.ack          = irq_ack;
    vec.private_data = state;

    //V3_Print("Raising host PCI IRQ %d\n", vec_index);

    if (state->pci_dev->irq_type == IRQ_NONE) {
        V3_Print("No IRQ type set\n");
        return 0;
    } else if (state->pci_dev->irq_type == IRQ_INTX) {
        v3_pci_raise_acked_irq(state->pci_bus, state->pci_dev, vec);
    } else {
        v3_pci_raise_irq(state->pci_bus, state->pci_dev, vec_index);
    }

    return 0;
}


static int 
host_pci_init(struct v3_vm_info * vm, 
	      v3_cfg_tree_t     * cfg) 
{
    struct host_pci_state * state  = V3_Malloc(sizeof(struct host_pci_state));
    struct vm_device      * dev    = NULL;
    struct vm_device      * pci    = v3_find_dev(vm, v3_cfg_val(cfg, "bus"));
    char                  * dev_id = v3_cfg_val(cfg, "ID");    
    char                  * url    = v3_cfg_val(cfg, "url");

    memset(state, 0, sizeof(struct host_pci_state));


    if (!pci) {
        PrintError("PCI bus not specified in config file\n");
        return -1;
    }

    state->pci_bus = pci;
    strncpy(state->name, dev_id, 32);


    dev = v3_add_device(vm, dev_id, &dev_ops, state);

    if (dev == NULL) {
        PrintError("Could not attach device %s\n", dev_id);
        V3_Free(state);
        return -1;
    }

    state->host_dev = v3_host_pci_get_dev(vm, url, state);

    if (state->host_dev == NULL) {
        PrintError("Could not connect to host pci device (%s)\n", url);
        return -1;
    }

    state->host_dev->irq_handler = irq_handler;

    if (setup_virt_pci_dev(vm, dev) == -1) {
        PrintError("Could not setup virtual host PCI device\n");
        return -1;
    }


    return 0;
}




device_register("HOST_PCI", host_pci_init)
