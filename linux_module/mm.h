/* Palacios memory manager 
 * (c) Jack Lange, 2010
 */

#ifndef PALACIOS_MM_H
#define PALACIOS_MM_H


/* 
 * Palacios Page Allocator
 *  - num_pages  : Number of pages to allocate
 *  - alignment  : byte alignment requirements for the base address
 *  - node_id    : The NUMA domain to allocate from (-1 = ANY)
 */
uintptr_t 
alloc_palacios_pgs(u64 num_pages, 
		   u32 alignment, 
		   int node_id);

/* 
 * Free Allocated Pages
 *  - base_addr  : Base address of the physically contiguous region
 *  - num_pages  : Number of pages to free 
 */
void 
free_palacios_pgs(uintptr_t base_addr, 
		  u64       num_pages);




/*
 * Add a physically contiguous memory region to Palacios' Page Allocator
 *  - base_addr  : Base address of physically contiguous region
 *  - num_pages  : Number of pages making up the region
 */
int 
add_palacios_memory(uintptr_t base_addr, 
		    u64       num_pages);


/*
 * Remove a physically contiguous memory region from Palacios' Page Allocator
 *  - base_addr  : Base address of physically contiguous region
 */
int 
remove_palacios_memory(uintptr_t base_addr);

/* 
 * Initialize Palacios memory management 
 */
int 
palacios_init_mm( void );

/* 
 * Deinitialize Palacios memory management 
 */
int 
palacios_deinit_mm( void );


/* 
 * Palacios wrapper for Linux's kmalloc function
 */
void * 
palacios_kmalloc(size_t size, 
		 gfp_t  flags);


/* 
 * Palacios wrapper for Linux's kfree function
 */
void 
palacios_kfree(void * ptr);


#endif
