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

#ifdef USE_VMM_PAGING_DEBUG

/* 
 * 
 *  This is an implementation file that gets included only in vmm_paging.c
 * 
 */


static void PrintPDE32(addr_t vaddr, pde32_t * pde) {
    PrintDebug("PDE[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, rsvd=%x, lg=%x, gl=%x, info=%x\n",
	       (int)PDE32_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t) (pde->pt_base_addr << PAGE_POWER),
	       pde->present,
	       pde->writable,
	       pde->user_page, 
	       pde->write_through,
	       pde->cache_disable,
	       pde->accessed,
	       pde->reserved,
	       pde->large_page,
	       pde->global_page,
	       pde->vmm_info);
}

  
static void PrintPTE32(addr_t vaddr, pte32_t * pte) {

    PrintDebug("PTE[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, d=%x, attr=%x, gl=%x, info=%x\n",
	       (int)PTE32_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t)(pte->page_base_addr << PAGE_POWER),
	       pte->present,
	       pte->writable,
	       pte->user_page,
	       pte->write_through,
	       pte->cache_disable,
	       pte->accessed,
	       pte->dirty,
	       pte->pte_attr,
	       pte->global_page,
	       pte->vmm_info);
}






static void PrintPDPE32PAE(addr_t vaddr, pdpe32pae_t * pdpe) {

    PrintDebug("PDPE[%d] va:%p -> pa:%p : present=%x, wt=%x, cd=%x, a=%x, info=%x\n",
	       (int)PDPE32PAE_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t) (pdpe->pd_base_addr << PAGE_POWER),
	       pdpe->present,
	       pdpe->write_through,
	       pdpe->cache_disable,
	       pdpe->accessed,
	       pdpe->vmm_info);
}

static void PrintPDE32PAE(addr_t vaddr, pde32pae_t * pde) {
    PrintDebug("PDE[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, lg=%x, gl=%x, info=%x\n",
	       (int)PDE32PAE_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t) (pde->pt_base_addr << PAGE_POWER),
	       pde->present,
	       pde->writable,
	       pde->user_page, 
	       pde->write_through,
	       pde->cache_disable,
	       pde->accessed,
	       pde->large_page,
	       pde->global_page,
	       pde->vmm_info);
}

  
static void PrintPTE32PAE(addr_t vaddr, pte32pae_t * pte) {
    PrintDebug("PTE[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, d=%x, attr=%x, gl=%x, info=%x\n",
	       (int)PTE32PAE_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t)(pte->page_base_addr << PAGE_POWER),
	       pte->present,
	       pte->writable,
	       pte->user_page,
	       pte->write_through,
	       pte->cache_disable,
	       pte->accessed,
	       pte->dirty,
	       pte->pte_attr,
	       pte->global_page,
	       pte->vmm_info);
}








static void PrintPML4e64(addr_t vaddr, pml4e64_t * pml) {

    PrintDebug("PML4e64[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, rsvd=%x, info=%x\n",
	       (int)PML4E64_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t) (BASE_TO_PAGE_ADDR(pml->pdp_base_addr)),
	       pml->present,
	       pml->writable,
	       pml->user_page, 
	       pml->write_through,
	       pml->cache_disable,
	       pml->accessed,
	       pml->reserved,
	       pml->vmm_info);
}

static void PrintPDPE64(addr_t vaddr, pdpe64_t * pdpe) {
    addr_t page_pa = 0;
    
    if (pdpe->large_page) {
	page_pa = BASE_TO_PAGE_ADDR_1GB(((pdpe64_1GB_t *)pdpe)->page_base_addr);
    } else {
	page_pa = BASE_TO_PAGE_ADDR(pdpe->pd_base_addr);
    }

    PrintDebug("PDPE64[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, rsvd=%x, lg=%x, gl/zero=%x, info=%x\n",
	       (int)PDPE64_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)page_pa,
	       pdpe->present,
	       pdpe->writable,
	       pdpe->user_page, 
	       pdpe->write_through,
	       pdpe->cache_disable,
	       pdpe->accessed,
	       pdpe->avail,
	       pdpe->large_page,
	       pdpe->zero,
	       pdpe->vmm_info);
}



static void PrintPDE64(addr_t vaddr, pde64_t * pde) {
    addr_t page_pa = 0;

    if (pde->large_page) {
	page_pa = BASE_TO_PAGE_ADDR_2MB(((pde64_2MB_t *)pde)->page_base_addr);
    } else {
	page_pa = BASE_TO_PAGE_ADDR(pde->pt_base_addr);
    }
    
    
    PrintDebug("PDE64[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, rsvd=%x, lg=%x, gl=%x, info=%x\n",
	       (int)PDE64_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)page_pa,
	       pde->present,
	       pde->writable,
	       pde->user_page, 
	       pde->write_through,
	       pde->cache_disable,
	       pde->accessed,
	       pde->avail,
	       pde->large_page,
	       pde->global_page,
	       pde->vmm_info);
}

  
static void PrintPTE64(addr_t vaddr, pte64_t * pte) {
    PrintDebug("PTE64[%d] va:%p -> pa:%p : present=%x, wr=%x, user=%x, wt=%x, cd=%x, a=%x, d=%x, attr=%x, gl=%x, info=%x\n",
	       (int)PTE64_INDEX(vaddr),
	       (void *)vaddr,
	       (void *)(addr_t)(BASE_TO_PAGE_ADDR(pte->page_base_addr)),
	       pte->present,
	       pte->writable,
	       pte->user_page,
	       pte->write_through,
	       pte->cache_disable,
	       pte->accessed,
	       pte->dirty,
	       pte->pte_attr,
	       pte->global_page,
	       pte->vmm_info);
}








static int print_page_walk_cb(struct v3_core_info * core, page_type_t type, addr_t vaddr, addr_t page_ptr, addr_t page_pa, void * private_data) {
    int i = 0;
    addr_t tmp_vaddr = 0;
    switch (type) {

	/* 64 Bit */

	case PAGE_PML464:
	    {
		pml4e64_t * pml = (pml4e64_t *)page_ptr;
		PrintDebug("PML4E64 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PML4E64_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_1GB * (uint64_t)MAX_PDPE64_ENTRIES * (uint64_t)i;
		    tmp_vaddr += vaddr;

		    if (tmp_vaddr & 0x0000800000000000ULL) {
			tmp_vaddr |= 0xffff000000000000ULL;
		    } else {
			tmp_vaddr &= 0x0000ffffffffffffULL;
		    }

		    if (pml[i].present) {
			PrintPML4e64(tmp_vaddr, &(pml[i]));
		    }
		}
		break;
	    }
	case PAGE_PDP64:
	    {
		pdpe64_t * pdp = (pdpe64_t *)page_ptr;
		PrintDebug("PDPE64 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PDPE64_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_1GB * i; 
		    tmp_vaddr += vaddr;

		    if (pdp[i].present) {
			PrintPDPE64(tmp_vaddr, &(pdp[i]));
		    }
		}
		break;
	    }
	case PAGE_PD64:
	    {
		pde64_t * pd = (pde64_t *)page_ptr;
		PrintDebug("PDE64 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PDE64_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_2MB * i; 
		    tmp_vaddr += vaddr;

		    if (pd[i].present) {
			PrintPDE64(tmp_vaddr, &(pd[i]));
		    }
		}
		break;
	    }
	case PAGE_PT64:
	    {
		pte64_t * pt = (pte64_t *)page_ptr;
		PrintDebug("PTE64 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PTE64_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_4KB * i; 
		    tmp_vaddr += vaddr;

		    if (pt[i].present) {
			PrintPTE64(tmp_vaddr, &(pt[i]));
		    }
		}
		break;
	    }

	    /* 32 BIT PAE */
    
	case PAGE_PDP32PAE:
	    {
		pdpe32pae_t * pdp = (pdpe32pae_t *)page_ptr;
		PrintDebug("PDPE32PAE (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PDPE32PAE_ENTRIES; i++) {
		    tmp_vaddr = 4096 * MAX_PTE32PAE_ENTRIES * MAX_PDE32PAE_ENTRIES * i; 
		    tmp_vaddr += vaddr;

		    if (pdp[i].present) {
			PrintPDPE32PAE(tmp_vaddr, &(pdp[i]));
		    }
		}
		break;
	    }
	case PAGE_PD32PAE:
	    {
		pde32pae_t * pd = (pde32pae_t *)page_ptr;
		PrintDebug("PDE32PAE (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PDE32PAE_ENTRIES; i++) {
		    tmp_vaddr = 4096 * MAX_PTE32PAE_ENTRIES * i; 
		    tmp_vaddr += vaddr;

		    if (pd[i].present) {
			PrintPDE32PAE(tmp_vaddr, &(pd[i]));
		    }
		}
		break;
	    }
	case PAGE_PT32PAE:
	    {
		pte32pae_t * pt = (pte32pae_t *)page_ptr;
		PrintDebug("PTE32PAE (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PTE32PAE_ENTRIES; i++) {
		    tmp_vaddr = 4096 * i; 
		    tmp_vaddr += vaddr;

		    if (pt[i].present) {
			PrintPTE32PAE(tmp_vaddr, &(pt[i]));
		    }
		}
		break;
	    }

	    /* 32 Bit */

	case PAGE_PD32:
	    {
		pde32_t * pd = (pde32_t *)page_ptr;
		PrintDebug("PDE32 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PTE32_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_4MB * i; 
		    tmp_vaddr += vaddr;

		    if (pd[i].present) {
			PrintPDE32(tmp_vaddr, &(pd[i]));
		    }
		}
		break;
	    }
	case PAGE_PT32:
	    {
		pte32_t * pt = (pte32_t *)page_ptr;
		PrintDebug("PTE32 (va=%p, pa=%p)\n", (void *)vaddr, (void *)page_pa);
		for (i = 0; i < MAX_PTE32_ENTRIES; i++) {
		    tmp_vaddr = PAGE_SIZE_4KB * i; 
		    tmp_vaddr += vaddr;

		    if (pt[i].present) {
			PrintPTE32(tmp_vaddr, &(pt[i]));
		    }
		}
		break;
	    }
	default:
	    break;
    }

    return 0;
}





static int print_page_tree_cb(struct v3_core_info * core, page_type_t type, addr_t vaddr, addr_t page_ptr, addr_t page_pa, void * private_data) {
    switch (type) {

	/* 64 Bit */

	case PAGE_PML464:
	    {
		pml4e64_t * pml = (pml4e64_t *)page_ptr;
		PrintPML4e64(vaddr, &(pml[PML4E64_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PDP64:
	    {
		pdpe64_t * pdp = (pdpe64_t *)page_ptr;
		PrintPDPE64(vaddr, &(pdp[PDPE64_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PD64:
	    {
		pde64_t * pd = (pde64_t *)page_ptr;
		PrintPDE64(vaddr, &(pd[PDE64_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PT64:
	    {
		pte64_t * pt = (pte64_t *)page_ptr;
		PrintPTE64(vaddr, &(pt[PTE64_INDEX(vaddr)]));
		break;
	    }

	    /* 32 BIT PAE */
    
	case PAGE_PDP32PAE:
	    {
		pdpe32pae_t * pdp = (pdpe32pae_t *)page_ptr;
		PrintPDPE32PAE(vaddr, &(pdp[PDPE32PAE_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PD32PAE:
	    {
		pde32pae_t * pd = (pde32pae_t *)page_ptr;
		PrintPDE32PAE(vaddr, &(pd[PDE32PAE_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PT32PAE:
	    {
		pte32pae_t * pt = (pte32pae_t *)page_ptr;
		PrintPTE32PAE(vaddr, &(pt[PTE32PAE_INDEX(vaddr)]));
		break;
	    }

	    /* 32 Bit */

	case PAGE_PD32:
	    {
		pde32_t * pd = (pde32_t *)page_ptr;
		PrintPDE32(vaddr, &(pd[PDE32_INDEX(vaddr)]));
		break;
	    }
	case PAGE_PT32:
	    {
		pte32_t * pt = (pte32_t *)page_ptr;
		PrintPTE32(vaddr, &(pt[PTE32_INDEX(vaddr)]));
		break;
	    }
	default:
	    PrintDebug("%s %p->%p \n", v3_page_type_to_str(type), (void *)vaddr, (void *)page_pa);
	    break;
    }

    return 0;
}



void v3_print_pt_entry(struct v3_core_info * core, page_type_t type, addr_t vaddr, void * entry) {
    print_page_tree_cb(core, type, vaddr, PAGE_ADDR_4KB((addr_t)entry), 0, NULL);
}


void v3_print_host_pgtables(struct v3_core_info * core, v3_cpu_mode_t cpu_mode, addr_t cr3) {
    PrintDebug("CR3: %p\n", (void *)cr3);
    switch (cpu_mode) {
	case PROTECTED:
	    v3_walk_host_pt_32(core, cr3, print_page_walk_cb, NULL);
	    break;
	case PROTECTED_PAE:
	    v3_walk_host_pt_32pae(core, cr3, print_page_walk_cb, NULL);
	    break;
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    v3_walk_host_pt_64(core, cr3, print_page_walk_cb, NULL);
	    break;
	default:
	    PrintError("Unsupported CPU MODE %s\n", v3_cpu_mode_to_str(core->cpu_mode));
	    break;
    }
}


void v3_print_guest_pgtables(struct v3_core_info * core, addr_t cr3) {
    PrintDebug("Guest Page Tables -- CR3: %p\n", (void *)cr3);
    switch (core->cpu_mode) {
	case REAL:
	case PROTECTED:
	    v3_walk_guest_pt_32(core, cr3, print_page_walk_cb, NULL);
	    break;
	case PROTECTED_PAE:
	    v3_walk_guest_pt_32pae(core, cr3, print_page_walk_cb, NULL);
	    break;
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    v3_walk_guest_pt_64(core, cr3, print_page_walk_cb, NULL);
	    break;
	default:
	    PrintError("Unsupported CPU MODE %s\n", v3_cpu_mode_to_str(core->cpu_mode));
	    break;
    }
}

void v3_print_host_pg_walk(struct v3_core_info * core,  addr_t virtual_addr, addr_t cr3) {
    PrintDebug("CR3: %p\n", (void *)cr3);
    switch (core->cpu_mode) {
	case PROTECTED:
	    v3_drill_host_pt_32(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	case PROTECTED_PAE:
	    v3_drill_host_pt_32pae(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    v3_drill_host_pt_64(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	default:
	    PrintError("Unsupported CPU MODE %s\n", v3_cpu_mode_to_str(core->cpu_mode));
	    break;
    }
}

void v3_print_guest_pg_walk(struct v3_core_info * core, addr_t virtual_addr, addr_t cr3) {
    PrintDebug("CR3: %p\n", (void *)cr3);
    switch (core->cpu_mode) {
	case PROTECTED:
	    v3_drill_guest_pt_32(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	case PROTECTED_PAE:
	    v3_drill_guest_pt_32pae(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    v3_drill_guest_pt_64(core, cr3, virtual_addr, print_page_tree_cb, NULL);
	    break;
	default:
	    PrintError("Unsupported CPU MODE %s\n", v3_cpu_mode_to_str(core->cpu_mode));
	    break;
    }
}


#endif
