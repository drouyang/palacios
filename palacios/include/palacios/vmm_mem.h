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


#ifndef __VMM_MEM_H
#define __VMM_MEM_H


#ifdef __V3VEE__ 


#include <palacios/vmm_types.h>

#include <palacios/vmm_paging.h>
#include <palacios/vmm_rbtree.h>
#include <palacios/vmm_list.h>

struct v3_core_info;
struct v3_vm_info;



#define V3_MEM_CORE_ANY ((uint16_t)-1)


// Memory region flags 
#define V3_MEM_RD     0x0001
#define V3_MEM_WR     0x0002
#define V3_MEM_EXEC   0x0004
#define V3_MEM_BASE   0x0008
#define V3_MEM_ALLOC  0x0010
#define V3_MEM_UC     0x0020



typedef struct {
    union {
	uint16_t value;
	struct {
	    // These reflect the VMM's intent for the shadow or nested pts 
	    // that will implement the region.   The guest's intent is in
	    // its own page tables.
	    uint16_t read   : 1;
	    uint16_t write  : 1;
	    uint16_t exec   : 1;
	    uint16_t base   : 1;
	    uint16_t alloced : 1;
	    uint16_t uncached : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) v3_mem_flags_t;



struct v3_mem_region {
    addr_t                  guest_start; 
    addr_t                  guest_end; 

    v3_mem_flags_t          flags;

    addr_t                  host_addr; // This either points to a host address mapping

    int (*unhandled)(struct v3_core_info * info, addr_t guest_va, addr_t guest_pa, 
		     struct v3_mem_region * reg, pf_error_t access_info);

    void * priv_data;

    int core_id;  // The virtual core this region is assigned to (-1 means all cores)
    int numa_id;  // The NUMA node this region is allocated from 

    struct rb_node tree_node; // This for memory regions mapped to the global map
};


struct v3_mem_map {

    struct rb_root mem_regions;

    uint32_t num_base_blocks;
    struct v3_mem_region * base_regions;
};


int v3_init_mem_map(struct v3_vm_info * vm);
void v3_delete_mem_map(struct v3_vm_info * vm);



#ifdef V3_CONFIG_CHECKPOINT
#include <palacios/vmm_checkpoint.h>
int v3_mem_save(struct v3_vm_info * vm, struct v3_chkpt * chkpt);
int v3_mem_load(struct v3_vm_info * vm, struct v3_chkpt * chkpt);
#endif

struct v3_mem_region * v3_create_mem_region(struct v3_vm_info * vm, uint16_t core_id, uint16_t flags,  
					       addr_t guest_addr_start, addr_t guest_addr_end);

int v3_insert_mem_region(struct v3_vm_info * vm, struct v3_mem_region * reg);

void v3_delete_mem_region(struct v3_vm_info * vm, struct v3_mem_region * reg);


/* This is a shortcut function for creating + inserting a memory region which redirects to host memory */
int v3_add_shadow_mem(struct v3_vm_info * vm, uint16_t core_id, uint16_t mem_flags, 
		      addr_t guest_addr_start, addr_t guest_addr_end, addr_t host_addr);



struct v3_mem_region * v3_get_mem_region(struct v3_vm_info * vm, uint16_t core_id, addr_t guest_addr);
struct v3_mem_region * v3_get_base_region(struct v3_vm_info * vm, addr_t gpa);


uint32_t v3_get_max_page_size(struct v3_core_info * core, addr_t fault_addr, v3_cpu_mode_t mode);


void v3_print_mem_map(struct v3_vm_info * vm);


int v3_mem_write(struct v3_core_info * core, addr_t gpa, uint8_t * src, uint64_t len);
int v3_mem_read(struct v3_core_info * core, addr_t gpa, uint8_t * src, uint64_t len);


#endif /* ! __V3VEE__ */


#endif
