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

#include <palacios/vm_guest_mem.h>
#include <palacios/vmm.h>
#include <palacios/vmm_paging.h>

#ifndef V3_CONFIG_DEBUG_MEM_ERRORS
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

extern struct v3_os_hooks * os_hooks;


/**********************************/
/* GROUP 0                        */
/**********************************/

int 
v3_hva_to_hpa(addr_t   hva, 
	      addr_t * hpa)
{
    if ((os_hooks) && (os_hooks)->vaddr_to_paddr) {

	*hpa = (addr_t)(os_hooks)->vaddr_to_paddr((void *)hva);
  
	if (*hpa == 0) {
	    PrintDebug("In HVA->HPA: Invalid HVA(%p)->HPA lookup\n",  
		       (void *)hva);
	    return -1;
	}
    } else {
	PrintDebug("In HVA->HPA: os_hooks not defined\n");
	return -1;
    }
    return 0;
}


int 
v3_hpa_to_hva(addr_t   hpa, 
	      addr_t * hva) 
{
    if ((os_hooks) && (os_hooks)->paddr_to_vaddr) {

	*hva = (addr_t)(os_hooks)->paddr_to_vaddr((void *)hpa);
    
	if (*hva == 0) {
	    PrintDebug("In HPA->HVA: Invalid HPA(%p)->HVA lookup\n",  
		       (void *)hpa);
	    return -1;
	}
    } else {
	PrintDebug("In HPA->HVA: os_hooks not defined\n");
	return -1;
    }
    return 0;
}

int 
v3_gpa_to_hpa(struct v3_core_info * core, 
	      addr_t                gpa, 
	      addr_t              * hpa) 
{
    struct v3_mem_region * reg = v3_get_mem_region(core->vm_info, core->vcpu_id, gpa);

    if (reg == NULL) {
	PrintDebug("In GPA->HPA: Could not find address in shadow map (addr=%p) (NULL REGION)\n", 
		   (void *)gpa);
	return -1;
    }
    
    if (reg->flags.alloced == 0) {
	//PrintDebug("In GPA->HPA: Tried to translate physical address of non allocated page (addr=%p)\n", 
	//	   (void *)gpa);
    //v3_print_mem_map(core->vm_info);
	return -1;
    }

    *hpa = reg->translate(core, gpa, reg);
    if (*hpa == (addr_t)0) {
	PrintError("Failed to translate HPA %p to GPA through region translation callback!!!\n", (void *)gpa);
	return -1;
    }

    return 0;
}


/* !! Currently not implemented !! */
// This is a scan of the shadow map
// For now we ignore it
// 
int 
v3_hpa_to_gpa(struct v3_core_info * v3_core_info, 
	      addr_t                hpa,
	      addr_t              * gpa) 
{
    *gpa = 0;
    PrintDebug("ERROR!!! HPA->GPA currently not implemented!!!\n");

    return -1;
}



/**********************************/
/* GROUP 1                        */
/**********************************/


/* !! Currently not implemented !! */
// This will return negative until we implement hpa_to_guest_pa()
int 
v3_hva_to_gpa(struct v3_core_info * v3_core_info, 
	      addr_t                hva, 
	      addr_t              * gpa) 
{
    addr_t hpa = 0;
    *gpa       = 0;

    if (v3_hva_to_hpa(hva, &hpa) != 0) {
	PrintDebug("In HVA->GPA: Invalid HVA(%p)->HPA lookup\n", 
		   (void *)hva);
	return -1;
    }

    if (v3_hpa_to_gpa(v3_core_info, hpa, gpa) != 0) {
	PrintDebug("In HVA->GPA: Invalid HPA(%p)->GPA lookup\n", 
		   (void *)hpa);
	return -1;
    }

    return 0;
}




int 
v3_gpa_to_hva(struct v3_core_info * core, 
	      addr_t                gpa, 
	      addr_t              * hva) 
{
    addr_t hpa = 0;
    *hva       = 0;

    if (v3_gpa_to_hpa(core, gpa, &hpa) != 0) {
	//	PrintDebug("In GPA->HVA: Invalid GPA(%p)->HPA lookup\n", 
	//	   (void *)gpa);
	return -1;
    }
  
    if (v3_hpa_to_hva(hpa, hva) != 0) {
	PrintDebug("In GPA->HVA: Invalid HPA(%p)->HVA lookup\n", 
		   (void *)hpa);
	return -1;
    }

    return 0;
}


int 
v3_gva_to_gpa(struct v3_core_info * core, 
	      addr_t                gva, 
	      addr_t              * gpa) 
{
    v3_reg_t guest_cr3 = 0;

    if (core->mem_mode == PHYSICAL_MEM) {
	// guest virtual address is the same as the physical
	*gpa = gva;
	return 0;
    }

    if (core->shdw_pg_mode == SHADOW_PAGING) {
	guest_cr3 = core->shdw_pg_state.guest_cr3;
    } else {
	guest_cr3 = core->ctrl_regs.cr3;
    }


    // Guest Is in Paged mode
    switch (core->cpu_mode) {
	case PROTECTED:
	    if (v3_translate_guest_pt_32(core, guest_cr3, gva, gpa) == -1) {
		PrintDebug("Could not translate addr (%p) through 32 bit guest PT at %p\n", 
			   (void *)gva, (void *)(addr_t)guest_cr3);
		return -1;
	    }
	    break;
	case PROTECTED_PAE:
	    if (v3_translate_guest_pt_32pae(core, guest_cr3, gva, gpa) == -1) {
		PrintDebug("Could not translate addr (%p) through 32 bitpae guest PT at %p\n", 
			   (void *)gva, (void *)(addr_t)guest_cr3);
		return -1;
	    }
	    break;
	case LONG:
	case LONG_32_COMPAT:
	case LONG_16_COMPAT:
	    if (v3_translate_guest_pt_64(core, guest_cr3, gva, gpa) == -1) {
		PrintDebug("Could not translate addr (%p) through 64 bit guest PT at %p\n", 
			   (void *)gva, (void *)(addr_t)guest_cr3);
		return -1;
	    }
	    break;
	default:
	    return -1;
    }
  
    return 0;
}



/* !! Currently not implemented !! */
/* This will be a real pain.... its your standard page table walker in guest memory
 * 
 * For now we ignore it...
 */
int 
v3_gpa_to_gva(struct v3_core_info * core, 
	      addr_t                gpa, 
	      addr_t              * gva) 
{
    *gva = 0;
    PrintDebug("ERROR!!: GPA->GVA Not Implemented!!\n");
    return -1;
}


/**********************************/
/* GROUP 2                        */
/**********************************/


int 
v3_gva_to_hpa(struct v3_core_info * core,
	      addr_t                gva, 
	      addr_t              * hpa) 
{
    addr_t gpa = 0;
    *hpa       = 0;

    if (v3_gva_to_gpa(core, gva, &gpa) != 0) {
	PrintDebug("In GVA->HPA: Invalid GVA(%p)->GPA lookup\n", 
		   (void *)gva);
	return -1;
    }
  
    if (v3_gpa_to_hpa(core, gpa, hpa) != 0) {
	PrintDebug("In GVA->HPA: Invalid GPA(%p)->HPA lookup\n", 
		   (void *)gpa);
	return -1;
    }

    return 0;
}

/* !! Currently not implemented !! */
int 
v3_hpa_to_gva(struct v3_core_info * core, 
	      addr_t                hpa, 
	      addr_t              * gva) 
{
    addr_t gpa = 0;
    *gva       = 0;

    if (v3_hpa_to_gpa(core, hpa, &gpa) != 0) {
	PrintDebug("In HPA->GVA: Invalid HPA(%p)->GPA lookup\n", 
		   (void *)hpa);
	return -1;
    }

    if (v3_gpa_to_gva(core, gpa, gva) != 0) {
	PrintDebug("In HPA->GVA: Invalid GPA(%p)->GVA lookup\n", 
		   (void *)gpa);
	return -1;
    }

    return 0;
}




int 
v3_gva_to_hva(struct v3_core_info * core, 
	      addr_t                gva, 
	      addr_t              * hva) 
{
    addr_t gpa = 0;
    addr_t hpa = 0;
    *hva       = 0;

    if (v3_gva_to_gpa(core, gva, &gpa) != 0) {
	PrintDebug("In GVA->HVA: Invalid GVA(%p)->GPA lookup\n", 
		   (void *)gva);
	return -1;
    }

    if (v3_gpa_to_hpa(core, gpa, &hpa) != 0) {
	PrintDebug("In GVA->HVA: Invalid GPA(%p)->HPA lookup\n", 
		   (void *)gpa);
	return -1;
    }

    if (v3_hpa_to_hva(hpa, hva) != 0) {
	PrintDebug("In GVA->HVA: Invalid HPA(%p)->HVA lookup\n", 
		   (void *)hpa);
	return -1;
    }

    return 0;
}


/* !! Currently not implemented !! */
int 
v3_hva_to_gva(struct v3_core_info * core, 
	      addr_t                hva, 
	      addr_t              * gva) 
{
    addr_t hpa = 0;
    addr_t gpa = 0;
    *gva       = 0;

    if (v3_hva_to_hpa(hva, &hpa) != 0) {
	PrintDebug("In HVA->GVA: Invalid HVA(%p)->HPA lookup\n", 
		   (void *)hva);
	return -1;
    }

    if (v3_hpa_to_gpa(core, hpa, &gpa) != 0) {
	PrintDebug("In HVA->GVA: Invalid HPA(%p)->GPA lookup\n", 
		   (void *)hva);
	return -1;
    }

    if (v3_gpa_to_gva(core, gpa, gva) != 0) {
	PrintDebug("In HVA->GVA: Invalid GPA(%p)->GVA lookup\n", 
		   (void *)gpa);
	return -1;
    }

    return 0;
}






/* This is a straight address conversion + copy, 
 *   except for the tiny little issue of crossing page boundries.....
 */
size_t 
v3_read_gva(struct v3_core_info * core, 
	    addr_t                gva, 
	    size_t                count, 
	    uint8_t             * dest) 
{
    addr_t cursor     = gva;
    size_t bytes_read = 0;

    while (count > 0) {
	uint32_t dist_to_pg_edge = (PAGE_ADDR(cursor) + PAGE_SIZE) - cursor;
	size_t   bytes_to_copy   = (dist_to_pg_edge > count) ? count : dist_to_pg_edge;
	addr_t   host_addr       = 0;

    
	if (v3_gva_to_hva(core, cursor, &host_addr) != 0) {
	    PrintDebug("Invalid GVA(%p)->HVA lookup\n", (void *)cursor);
	    return bytes_read;
	}
    
	memcpy(dest + bytes_read, (void *)host_addr, bytes_to_copy);
    
	bytes_read += bytes_to_copy;
	count      -= bytes_to_copy;
	cursor     += bytes_to_copy;    
    }

    return bytes_read;
}






/* This is a straight address conversion + copy, 
 *   except for the tiny little issue of crossing page boundries.....
 */
size_t 
v3_read_gpa(struct v3_core_info * core,
	    addr_t                gpa, 
	    size_t                count, 
	    uint8_t             * dest) 
{
    addr_t cursor     = gpa;
    size_t bytes_read = 0;

    while (count > 0) {
	uint32_t dist_to_pg_edge = (PAGE_ADDR(cursor) + PAGE_SIZE) - cursor;
	size_t   bytes_to_copy   = (dist_to_pg_edge > count) ? count : dist_to_pg_edge;
	addr_t   host_addr       = 0;

	if (v3_gpa_to_hva(core, cursor, &host_addr) != 0) {
	    return bytes_read;
	}    
    
	memcpy(dest + bytes_read, (void *)host_addr, bytes_to_copy);

	bytes_read += bytes_to_copy;
	count      -= bytes_to_copy;
	cursor     += bytes_to_copy;
    }

    return bytes_read;
}


/* This clones v3_read_gva_memory
 *   We write only as far as page translations are available 
 */
size_t
v3_write_gva(struct v3_core_info * core,
	     addr_t                gva, 
	     size_t                count,
	     uint8_t             * src) 
{
    addr_t cursor        = gva;
    size_t bytes_written = 0;



    while (count > 0) {
	uint32_t dist_to_pg_edge = (PAGE_ADDR(cursor) + PAGE_SIZE) - cursor;
	size_t   bytes_to_copy   = (dist_to_pg_edge > count) ? count : dist_to_pg_edge;
	addr_t   host_addr       = 0;

    
	if (v3_gva_to_hva(core, cursor, &host_addr) != 0) {
	    PrintDebug("Invalid GVA(%p)->HVA lookup\n", (void *)cursor);
	    return bytes_written;
	}
    
    
	memcpy((void *)host_addr, src + bytes_written, bytes_to_copy);
    
	bytes_written += bytes_to_copy;
	count         -= bytes_to_copy;
	cursor        += bytes_to_copy;    
    }

    return bytes_written;
}




/* This is a straight address conversion + copy, 
 *   except for the tiny little issue of crossing page boundries.....
 */
size_t 
v3_write_gpa(struct v3_core_info * core, 
	     addr_t                gpa, 
	     size_t                count, 
	     uint8_t             * src) 
{
    addr_t cursor        = gpa;
    size_t bytes_written = 0;

    while (count > 0) {
	uint32_t dist_to_pg_edge = (PAGE_ADDR(cursor) + PAGE_SIZE) - cursor;
	size_t   bytes_to_copy   = (dist_to_pg_edge > count) ? count : dist_to_pg_edge;
	addr_t   host_addr       = 0;

	if (v3_gpa_to_hva(core, cursor, &host_addr) != 0) {
	    return bytes_written;
	}


	memcpy((void *)host_addr, src + bytes_written, bytes_to_copy);

	bytes_written += bytes_to_copy;
	count         -= bytes_to_copy;
	cursor        += bytes_to_copy;    
    }

    return bytes_written;
}

