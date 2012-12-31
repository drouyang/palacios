/* Palacios memory manager 
 * (c) Jack Lange, 2010
 */

#include <asm/page_64_types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
//static struct list_head pools;

#include "palacios.h"
#include "mm.h"
#include "buddy.h"


static struct buddy_memzone * memzone = NULL;
static uintptr_t seed_addr = 0;


// alignment is in bytes
uintptr_t alloc_palacios_pgs(u64 num_pages, u32 alignment) {
    uintptr_t addr = 0;

    BUG_ON(!memzone);

    printk("Allocating %llu pages (%llu bytes) order=%d\n", 
	   num_pages, num_pages * PAGE_SIZE, get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT);

    addr = buddy_alloc(memzone, get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT);
    
    if (!addr) {
	ERROR("Returning from alloc addr=%p, vaddr=%p\n", (void *)addr, __va(addr));
    }

    return addr;
}



void free_palacios_pgs(uintptr_t pg_addr, u64 num_pages) {
    //DEBUG("Freeing Memory page %p\n", (void *)pg_addr);
    
    buddy_free(memzone, pg_addr, get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT);
}


int add_palacios_memory(uintptr_t base_addr, u64 num_pages) {
    int pool_order = 0;

    DEBUG("Managing %dMB of memory starting at %llu (%lluMB)\n", 
	  (unsigned int)(num_pages * PAGE_SIZE) / (1024 * 1024), 
	  (unsigned long long)base_addr, 
	  (unsigned long long)(base_addr / (1024 * 1024)));


    //   pool_order = fls(num_pages); 

   pool_order = get_order(num_pages * PAGE_SIZE) + PAGE_SHIFT;

   buddy_add_pool(memzone, base_addr, pool_order);
   
   return 0;
}






int palacios_remove_memory(uintptr_t base_addr) {
    buddy_remove_pool(memzone, base_addr, 0);

    return 0;
}


int palacios_init_mm( void ) {

    // Seed the allocator with a small set of pages to allow initialization to complete. 
    // For now we will just grab some random pages, but in the future we will need to grab NUMA specific regions
    // See: alloc_pages_node()

    {
	struct page * pgs = alloc_pages(GFP_KERNEL, MAX_ORDER - 1);
	
	if (!pgs) {
	    ERROR("Could not allocate initial memory block\n");
	    BUG_ON(!pgs);
	    while (1);
	    return -1;
	}
	
	seed_addr = page_to_pfn(pgs) << PAGE_SHIFT;	
    }

    printk("Allocated seed region\n");
    printk("Initializing Zone\n");

    memzone = buddy_init(get_order(V3_CONFIG_MEM_BLOCK_SIZE) + PAGE_SHIFT, PAGE_SHIFT);

    if (memzone == NULL) {
	ERROR("Could not initialization memory management\n");
	return -1;
    }

    printk("Zone initialized, Adding seed region (order=%d)\n", 
	   (MAX_ORDER - 1) + PAGE_SHIFT);

    buddy_add_pool(memzone, seed_addr, (MAX_ORDER - 1) + PAGE_SHIFT);

    alloc_palacios_pgs(5, 4096);



    alloc_palacios_pgs(32, 4096);



    return 0;
}

int palacios_deinit_mm( void ) {

    buddy_deinit(memzone);

    // note that the memory is not onlined here - offlining and onlining
    // is the resposibility of the caller
    
    // free the seed regions
    free_pages(seed_addr, MAX_ORDER);

    return 0;
}






void * palacios_kmalloc(size_t size, gfp_t flags) {

    if (irqs_disabled() && ((flags & GFP_ATOMIC) == 0)) {
	WARNING("Allocating memory with Interrupts disabled!!!\n");
	WARNING("This is probably NOT want you want to do 99%% of the time\n");
	WARNING("If still want to do this, you may dismiss this warning by setting the GFP_ATOMIC flag directly\n");
	dump_stack();

	flags &= ~GFP_KERNEL;
	flags |= GFP_ATOMIC;
    }

    return kmalloc(size, flags);
}


void palacios_kfree(void * ptr) {

    return kfree(ptr);
}


