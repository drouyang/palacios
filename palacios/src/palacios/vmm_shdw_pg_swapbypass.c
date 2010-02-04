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

#include <palacios/vmm_shadow_paging.h>


struct shadow_page_data {
    v3_reg_t cr3;
    addr_t page_pa;
  
    struct list_head page_list_node;
};


struct vtlb_state {
 
    struct list_head page_list;

};


static struct shadow_page_data * create_new_shadow_pt(struct guest_info * info);


#include "vmm_shdw_pg_tlb_32.h"
#include "vmm_shdw_pg_tlb_32pae.h"
#include "vmm_shdw_pg_tlb_64.h"


static struct shadow_page_data * create_new_shadow_pt(struct guest_info * info) {
    struct shadow_page_state * state = &(info->shdw_pg_state);
    v3_reg_t cur_cr3 = info->ctrl_regs.cr3;
    struct shadow_page_data * page_tail = NULL;
    addr_t shdw_page = 0;

    if (!list_empty(&(state->page_list))) {
	page_tail = list_tail_entry(&(state->page_list), struct shadow_page_data, page_list_node);
    
	if (page_tail->cr3 != cur_cr3) {
	    PrintDebug("Reusing old shadow Page: %p (cur_CR3=%p)(page_cr3=%p) \n",
		       (void *)(addr_t)page_tail->page_pa, 
		       (void *)(addr_t)cur_cr3, 
		       (void *)(addr_t)(page_tail->cr3));

	    list_move(&(page_tail->page_list_node), &(state->page_list));

	    memset(V3_VAddr((void *)(page_tail->page_pa)), 0, PAGE_SIZE_4KB);


	    return page_tail;
	}
    }

    // else  

    page_tail = (struct shadow_page_data *)V3_Malloc(sizeof(struct shadow_page_data));
    page_tail->page_pa = (addr_t)V3_AllocPages(1);

    PrintDebug("Allocating new shadow Page: %p (cur_cr3=%p)\n", 
	       (void *)(addr_t)page_tail->page_pa, 
	       (void *)(addr_t)cur_cr3);

    page_tail->cr3 = cur_cr3;
    list_add(&(page_tail->page_list_node), &(state->page_list));

    shdw_page = (addr_t)V3_VAddr((void *)(page_tail->page_pa));
    memset((void *)shdw_page, 0, PAGE_SIZE_4KB);

    return page_tail;
}



static int vtlb_init(struct v3_vm_info * vm, v3_cfg_tree_t * cfg, void ** priv_data) {
    struct vtlb_state * state = V3_Malloc(sizeof(struct vtlb_state));

    INIT_LIST_HEAD(&(state->page_list));

    *priv_data = state;

    return 0;
}


int vtlb_activate_shdw_pt(struct guest_info * core, void * priv_data) {
    switch (v3_get_vm_cpu_mode(core)) {

	case PROTECTED:
	    return activate_shadow_pt_32(core);
	case PROTECTED_PAE:
	    return activate_shadow_pt_32pae(core);
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    return activate_shadow_pt_64(core);
	default:
	    PrintError("Invalid CPU mode: %s\n", v3_cpu_mode_to_str(v3_get_vm_cpu_mode(core)));
	    return -1;
    }

    return 0;
}

int vtlb_invalidate_shdw_pt(struct guest_info * core, void * priv_data) {
    return vtlb_activate_shdw_pt(core, priv_data);
}


int vtlb_handle_pf(struct guest_info * core, addr_t fault_addr, pf_error_t err_code, void * priv_data) {

	switch (v3_get_vm_cpu_mode(core)) {
	    case PROTECTED:
		return handle_shadow_pagefault_32(core, fault_addr, error_code);
		break;
	    case PROTECTED_PAE:
		return handle_shadow_pagefault_32pae(core, fault_addr, error_code);
	    case LONG:
	    case LONG_32_COMPAT:
	    case LONG_16_COMPAT:
		return handle_shadow_pagefault_64(core, fault_addr, error_code);
		break;
	    default:
		PrintError("Unhandled CPU Mode: %s\n", v3_cpu_mode_to_str(v3_get_vm_cpu_mode(core)));
		return -1;
	}
}


int vtlb_handle_invlpg(struct guest_info * core, addr_t vaddr, void * priv_data) {

    switch (v3_get_vm_cpu_mode(core)) {
	case PROTECTED:
	    return handle_shadow_invlpg_32(core, vaddr);
	case PROTECTED_PAE:
	    return handle_shadow_invlpg_32pae(core, vaddr);
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    return handle_shadow_invlpg_64(core, vaddr);
	default:
	    PrintError("Invalid CPU mode: %s\n", v3_cpu_mode_to_str(v3_get_vm_cpu_mode(core)));
	    return -1;
    }
}