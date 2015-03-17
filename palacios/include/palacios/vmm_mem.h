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


/* Memory region flags */
#define V3_MEM_RD     0x0001          /* Readable     */
#define V3_MEM_WR     0x0002          /* Writable     */
#define V3_MEM_EXEC   0x0004          /* Executable   */
#define V3_MEM_BASE   0x0008          /* This region is a base region             */
#define V3_MEM_ALLOC  0x0010          /* This region is backed by physical memory */
#define V3_MEM_UC     0x0020          /* Disable caching of this memory region    */



typedef struct {
    union {
	uint16_t value;
	struct {
	    uint16_t read      : 1;   /* Readable     */
	    uint16_t write     : 1;   /* Writable     */
	    uint16_t exec      : 1;   /* Executable   */
	    uint16_t base      : 1;   /* This region is a base region             */
	    uint16_t alloced   : 1;   /* This region is backed by physical memory */
	    uint16_t uncached  : 1;   /* Disable caching of this memory region    */
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) v3_mem_flags_t;



struct v3_mem_region {
    addr_t                  guest_start; 
    addr_t                  guest_end; 

    v3_mem_flags_t          flags;

    addr_t                  host_addr;    

    int (*unhandled)(struct v3_core_info  * info, 
		     addr_t                 guest_va, 
		     addr_t                 guest_pa, 
		     struct v3_mem_region * reg, 
		     pf_error_t             access_info);

    int (*translate)(struct v3_core_info  * info,
		     struct v3_mem_region * reg,
		     addr_t                 guest_pa,
		     addr_t               * host_pa);

    void * priv_data;

    int core_id;                         /* The virtual core this region is assigned to (-1 means all cores) */
    int numa_id;                         /* The NUMA node this region is allocated from                      */

    struct rb_node tree_node;            /* This for memory regions mapped to the global map                 */
};



/*
 * There are two layers of memory regions in Palacios
 * -- The base regions are fixed sized blocks preallocated at initialization time
 *        and cover the entirety of the guest's physical memory 
 * 
 * -- A red-black tree of overlay regions that supersede the base regions and 
 *        and can be created at any time
 */
struct v3_mem_map {
    struct rb_root         mem_regions;      /* Red black tree regions, overlaid on the base regions */

    uint32_t               num_base_blocks;  /* Number of base regions spanning guest's physical mem */
    struct v3_mem_region * base_regions;     /* A pointer to an array of fixed size base regions     */
};


int 
v3_init_mem_map(struct v3_vm_info * vm);


void 
v3_delete_mem_map(struct v3_vm_info * vm);



struct v3_mem_region * 
v3_create_mem_region(struct v3_vm_info * vm, 
		     uint16_t            core_id, 
		     uint16_t            flags,  
		     addr_t              gpa_start, 
		     addr_t              gpa_end);

int
v3_insert_mem_region(struct v3_vm_info    * vm, 
		     struct v3_mem_region * reg);

void 
v3_delete_mem_region(struct v3_vm_info    * vm, 
		     struct v3_mem_region * reg);


/**
 *  This is a shortcut function for creating + inserting
 *   a memory region which redirects to host memory 
 */
int 
v3_add_shadow_mem(struct v3_vm_info * vm, 
		  uint16_t            core_id,
		  uint16_t            mem_flags, 
		  addr_t              gpa_start, 
		  addr_t              gpa_end, 
		  addr_t              hpa);



struct v3_mem_region * 
v3_get_mem_region(struct v3_vm_info * vm, 
		  uint16_t            core_id, 
		  addr_t              guest_addr);

struct v3_mem_region * 
v3_get_base_region(struct v3_vm_info * vm, 
		   addr_t              gpa);


uint32_t 
v3_get_max_page_size(struct v3_core_info * core, 
		     addr_t                fault_addr, 
		     v3_cpu_mode_t         mode);


void v3_print_mem_map(struct v3_vm_info * vm);





#endif /* ! __V3VEE__ */


#endif
