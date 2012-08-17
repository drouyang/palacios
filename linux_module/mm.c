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

#define OFFLINE_POOL_THRESHOLD 12

struct mempool {
    uintptr_t base_addr;
    u64 num_pages;

    u8 * bitmap;
};


static struct mempool pool;

static inline int get_page_bit(int index) {
    int major = index / 8;
    int minor = index % 8;

    return (pool.bitmap[major] & (0x1 << minor));
}

static inline void set_page_bit(int index) {
    int major = index / 8;
    int minor = index % 8;

    pool.bitmap[major] |= (0x1 << minor);
}

static inline void clear_page_bit(int index) {
    int major = index / 8;
    int minor = index % 8;

    pool.bitmap[major] &= ~(0x1 << minor);
}


uintptr_t get_palacios_base_addr(void) {
    return pool.base_addr;
}

u64 get_palacios_num_pages(void) {
    return pool.num_pages;
}


static uintptr_t alloc_contig_pgs(u64 num_pages, u32 alignment) {
    int step = 1;
    int i = 0;
    int start = 0;

    DEBUG("Allocating %llu pages (align=%lu)\n", 
	   num_pages, (unsigned long)alignment);

    if (pool.bitmap == NULL) {
	ERROR("ERROR: Attempting to allocate from non initialized memory\n");
	return 0;
    }

    if (alignment > 0) {
	step = alignment / PAGE_SIZE;
    }

    // Start the search at the correct alignment 
    if (pool.base_addr % alignment) {
	start = ((alignment - (pool.base_addr % alignment)) >> 12);
    }

    DEBUG("\t Start idx %d (base_addr=%p)\n", start, (void *)(u64)pool.base_addr);

    for (i = start; i < (pool.num_pages - num_pages); i += step) {
	if (get_page_bit(i) == 0) {
	    int j = 0;
	    int collision = 0;

	    for (j = i; (j - i) < num_pages; j++) {
		if (get_page_bit(j) == 1) {
		    collision = 1;
		    break;
		}
	    }

	    if (collision == 1) {
		break;
	    }

	    for (j = i; (j - i) < num_pages; j++) {
		set_page_bit(j);
	    }

	    return pool.base_addr + (i * PAGE_SIZE);
	}
    }

    ERROR("ALERT ALERT Allocation of Large Number of Contiguous Pages FAILED\n"); 

    return 0;
}


// alignment is in bytes
uintptr_t alloc_palacios_pgs(u64 num_pages, u32 alignment) {
    uintptr_t addr = 0; 

    if (num_pages < OFFLINE_POOL_THRESHOLD) {
	struct page * pgs = NULL;
	void *temp;
	int order = get_order(num_pages * PAGE_SIZE);
	 
	pgs = alloc_pages(GFP_DMA32, order);
    
	if (!pgs) { 
	    ERROR("Could not allocate small number of contigious pages\n");
	    return 0;
	}
 
	/* DEBUG("%llu pages (order=%d) aquired from alloc_pages\n", 
	       num_pages, order); */

	addr = page_to_pfn(pgs) << PAGE_SHIFT; 

	temp = (void*)addr;

	if ( (temp>=(void*)(pool.base_addr) && 
	      (temp<((void*)(pool.base_addr)+pool.num_pages*PAGE_SIZE))) 
	     || ((temp+num_pages*PAGE_SIZE)>=(void*)(pool.base_addr) && 
		 ((temp+num_pages*PAGE_SIZE)<((void*)(pool.base_addr)+pool.num_pages*PAGE_SIZE))) ) {

	    ERROR("ALERT ALERT Allocation of small number of contiguous pages returned block that "
		  "OVERLAPS with the offline page pool addr=%p, addr+numpages=%p, "
		  "pool.base_addr=%p, pool.base_addr+pool.numpages=%p\n", 
		  temp, temp+num_pages*PAGE_SIZE, (void*)(pool.base_addr), 
		  (void*)(pool.base_addr)+pool.num_pages*PAGE_SIZE);
	}

	
    } else {
	//DEBUG("Allocating %llu pages from bitmap allocator\n", num_pages);
	//addr = pool.base_addr;
	addr = alloc_contig_pgs(num_pages, alignment);
	if (!addr) { 
	    ERROR("Could not allocate large number of contiguous pages\n");
	}
    }


    //DEBUG("Returning from alloc addr=%p, vaddr=%p\n", (void *)addr, __va(addr));
    return addr;
}



void free_palacios_pgs(uintptr_t pg_addr, u64 num_pages) {
    //DEBUG("Freeing Memory page %p\n", (void *)pg_addr);

    if ((pg_addr >= pool.base_addr) && 
	(pg_addr < pool.base_addr + (PAGE_SIZE * pool.num_pages))) {
	int pg_idx = (pg_addr - pool.base_addr) / PAGE_SIZE;
	int i = 0;


	if (num_pages<OFFLINE_POOL_THRESHOLD) { 
	    ERROR("ALERT ALERT  small page deallocation from offline pool\n");
	    return;
        }	

	if ((pg_idx + num_pages) > pool.num_pages) {
	    ERROR("Freeing memory bounds exceeded for offline pool\n");
	    return;
	}

	for (i = 0; i < num_pages; i++) {
	    if (get_page_bit(pg_idx + i) == 0) { 
		ERROR("Trying to free unallocated page from offline pool\n");
	    }
	    clear_page_bit(pg_idx + i);
	}
	
    } else {
	if (num_pages>=OFFLINE_POOL_THRESHOLD) {
	   ERROR("ALERT ALERT Large page deallocation from linux pool\n");
	}
	__free_pages(pfn_to_page(pg_addr >> PAGE_SHIFT), get_order(num_pages * PAGE_SIZE));
    }
}


int add_palacios_memory(uintptr_t base_addr, u64 num_pages) {
    /* JRL: OK.... so this is horrible, terrible and if anyone else did it I would yell at them.
     * But... the fact that you can do this in C is so ridiculous that I can't help myself.
     * Note that we're repurposing "true" to be 1 here
     */

    int bitmap_size = (num_pages / 8) + ((num_pages % 8) > 0); 

    if (pool.num_pages != 0) {
	ERROR("ERROR: Memory has already been added\n");
	return -1;
    }

    DEBUG("Managing %dMB of memory starting at %llu (%lluMB)\n", 
	   (unsigned int)(num_pages * PAGE_SIZE) / (1024 * 1024), 
	   (unsigned long long)base_addr, 
	   (unsigned long long)(base_addr / (1024 * 1024)));


    pool.bitmap = palacios_kmalloc(bitmap_size, GFP_KERNEL);
    
    if (IS_ERR(pool.bitmap)) {
	ERROR("Error allocating Palacios MM bitmap\n");
	return -1;
    }
    
    memset(pool.bitmap, 0, bitmap_size);

    pool.base_addr = base_addr;
    pool.num_pages = num_pages;

    return 0;
}



int palacios_init_mm( void ) {

    pool.base_addr = 0;
    pool.num_pages = 0;
    pool.bitmap = NULL;

    return 0;
}

int palacios_deinit_mm( void ) {

    palacios_kfree(pool.bitmap);

    pool.bitmap=0;
    pool.base_addr=0;
    pool.num_pages=0;

    // note that the memory is not onlined here - offlining and onlining
    // is the resposibility of the caller
    
    return 0;
}




#ifdef V3_CONFIG_DEBUG_MEM_PARANOID
// The following can be used to track heap bugs
// zero memory after allocation
#define ALLOC_ZERO_MEM 0
// pad allocations by this many bytes on both ends of block
#define ALLOC_PAD      0

static void * palacios_kmalloc_paranoid(size_t size, gfp_t flags) {
    void * addr = NULL;

    addr = kmalloc(size+2*ALLOC_PAD, flags);
    
    if (!addr) { 
	ERROR("ALERT ALERT  kmalloc has FAILED FAILED FAILED\n");
	return NULL;
    }	
    

    
#if ALLOC_ZERO_MEM
    memset(addr, 0, size + 2 * ALLOC_PAD);
#endif
    
    return addr + ALLOC_PAD;

}

static void palacios_kfree_paranoid(void * ptr) {
    kfree(addr - ALLOC_PAD);
}

#endif

void * palacios_kmalloc(size_t size, gfp_t flags) {

    if (irqs_disabled() && ((flags & GFP_ATOMIC) == 0)) {
	WARNING("Allocating memory with Interrupts disabled!!!\n");
	WARNING("This is probably NOT want you want to do 99%% of the time\n");
	WARNING("If still want to do this, you may dismiss this warning by setting the GFP_ATOMIC flag directly\n");
	dump_stack();

	flags &= ~GFP_KERNEL;
	flags |= GFP_ATOMIC;
    }

#ifdef V3_CONFIG_DEBUG_MEM_PARANOID
    return palacios_kmalloc_paranoid(size, flags);
#else
    return kmalloc(size, flags);
#endif
}


void palacios_kfree(void * ptr) {
#ifdef V3_CONFIG_DEBUG_MEM_PARANOID
    return palacios_kfree_paranoid(ptr);
#else
    return kfree(ptr);
#endif

}


