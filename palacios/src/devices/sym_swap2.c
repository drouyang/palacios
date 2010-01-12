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

#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <palacios/vmm_sym_swap.h>
#include <palacios/vm_guest.h>
#include <palacios/vmm_hashtable.h>


#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY
#include <palacios/vmm_telemetry.h>
#endif


#undef PrintDebug
#define PrintDebug(fmt, ...)


/* This is the first page that linux writes to the swap area */
/* Taken from Linux */
union swap_header {
    struct {
	char reserved[PAGE_SIZE - 10];
	char magic[10];			/* SWAP-SPACE or SWAPSPACE2 */
    } magic;
    struct {
	char	         	bootbits[1024];	/* Space for disklabel etc. */
	uint32_t		version;
	uint32_t		last_page;
	uint32_t		nr_badpages;
	unsigned char   	sws_uuid[16];
	unsigned char	        sws_volume[16];
	uint32_t                type;           // The index into the swap_map
	uint32_t		padding[116];

	uint32_t		badpages[1];
    } info;
};


struct cache_entry {
    uint32_t disk_index;
    struct list_head cache_node;
};

// Per instance data structure
struct swap_state {
    int active;
    int disabled;

    struct guest_info * vm;
    struct swap_state * swap_info;

    int symbiotic;

    union swap_header hdr;

    uint_t swapped_pages;
    uint_t unswapped_pages;
    uint32_t disk_writes;
    uint32_t disk_reads;


    uint32_t seek_usecs;

    struct v3_dev_blk_ops * ops;
    void * private_data;

#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY
    uint32_t pages_in;
    uint32_t pages_out;
#endif

    int io_flag;

    uint64_t cache_size;
    uint8_t * cache;
    uint64_t cache_base_addr;
    uint_t pages_in_cache;

    struct cache_entry * entry_map;
    struct list_head entry_list;
    struct list_head free_list;

    struct hashtable * entry_ht;
};



void __udelay(unsigned long usecs);

static uint_t cache_hash_fn(addr_t key) {
    return v3_hash_long(key, 32);
}


static int cache_eq_fn(addr_t key1, addr_t key2) {
    return (key1 == key2);
}





static inline uint32_t get_swap_index_from_offset(uint32_t offset) {
    // CAREFUL: The index might be offset by 1, because the first 4K is the header
    return (offset / 4096);
}

static inline uint32_t get_swap_offset_from_index(uint32_t index) {
    // CAREFUL: The index might be offset by 1, because the first 4K is the header
    return (index * 4096);
}


static inline uint32_t get_cache_entry_index(struct swap_state * swap, struct cache_entry * entry) {
    return (entry - swap->entry_map); // / sizeof(struct cache_entry);
}





static inline void * get_swap_entry(uint32_t pg_index, void * private_data) {
    struct swap_state * swap = (struct swap_state *)private_data;
    struct cache_entry * entry = NULL;
    void * pg_addr = NULL;
    uint32_t swap_index = pg_index * 4096;

    if (swap->disabled) {
	return NULL;
    }

    PrintDebug("Getting swap entry for index %d\n", pg_index);

    entry = (struct cache_entry *)v3_htable_search(swap->entry_ht, swap_index);

    if (entry != NULL) {
	uint32_t cache_index = get_cache_entry_index(swap, entry);
	PrintDebug("Found cached entry (%d)\n", cache_index);
	pg_addr = swap->cache + (cache_index * 4096);
    }

    return pg_addr;
}



static int read_disk(uint8_t * buf, uint64_t lba, uint64_t num_bytes, struct swap_state * swap) {
    if ((swap->io_flag == 0) && (swap->seek_usecs > 0)) {
	__udelay(swap->seek_usecs);
	swap->io_flag = 1;
    }

    swap->disk_reads += num_bytes / 4096;
    return swap->ops->read(buf, lba, num_bytes, swap->private_data);

}


static int write_disk(uint8_t * buf, uint64_t lba, uint64_t num_bytes, struct swap_state * swap) {
    if ((swap->io_flag == 0) && (swap->seek_usecs > 0)) {
	__udelay(swap->seek_usecs);
	swap->io_flag = 1;
    }
    
    swap->disk_writes += num_bytes / 4096;


    return swap->ops->write(buf, lba, num_bytes, swap->private_data);
}


static uint64_t swap_get_capacity(void * private_data) {
    struct swap_state * swap = (struct swap_state *)private_data;
    return swap->ops->get_capacity(swap->private_data);
}


static struct v3_swap_ops swap_ops = {
    .get_swap_entry = get_swap_entry,
};



static int buf_read(uint8_t * buf, uint64_t lba, uint64_t num_bytes, void * private_data) {
    struct swap_state * swap = (struct swap_state *)private_data;
    uint32_t offset = lba;
    uint32_t length = num_bytes;

    swap->io_flag = 0;

    if (length % 4096) {
	PrintError("Swapping in length that is not a page multiple\n");
    }

    if (swap->disabled) {
	return read_disk(buf, lba, num_bytes, swap);
    }


    PrintDebug("SymSwap: Reading %d bytes to %p (lba=%p)\n", (uint32_t)num_bytes, buf, (void *)(addr_t)lba);
	

    if (length % 4096) {
	PrintError("Swapping in length that is not a page multiple\n");
	return -1;
    }


    if ((swap->active == 1) && (offset >= 4096)) { 
	int i = 0;
	int read_pages = (length / 4096);
	

	// Notify the shadow paging layer
	
	swap->unswapped_pages += (length / 4096);


#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY
	swap->pages_in += length / 4096;
#endif

	for (i = 0; i < read_pages; i++) {
	    uint32_t swap_index = offset + (i * 4096);
	    uint32_t cache_index = 0;
	    struct cache_entry * entry = NULL;

	    if (swap->symbiotic == 1) {
		v3_swap_in_notify(swap->vm, get_swap_index_from_offset(offset + i), swap->hdr.info.type);
	    }	    

	    PrintDebug("Searching for swap index %d\n", swap_index);

	    entry = (struct cache_entry *)v3_htable_search(swap->entry_ht, (addr_t)swap_index);

	    if (entry != NULL) {
		
		cache_index = get_cache_entry_index(swap, entry);
		
		PrintDebug("Reading from cache entry %d\n", cache_index);

		memcpy(buf, swap->cache + (cache_index * 4096), 4096);

	    } else {
		PrintDebug("Reading from disk offset = %p\n", (void *)(addr_t)offset); 

		if (read_disk(buf, offset, 4096, swap) == -1) {
		    PrintError("Error reading disk\n");
		    return -1;
		}
	    }

	    offset += 4096;
	    buf += 4096;			  
	}
    } else {
	return read_disk(buf, lba, num_bytes, swap);
    }


    return 0;
}


static int flush_cache(struct swap_state * swap, int num_to_flush) {
    int i;

    PrintDebug("Flushing %d pages\n", num_to_flush);

    for (i = 0; i < num_to_flush; i++) {
	struct cache_entry * entry = NULL;
	uint32_t entry_index = 0;

 	entry = list_first_entry(&(swap->entry_list), struct cache_entry, cache_node);

	entry_index = get_cache_entry_index(swap, entry);
	PrintDebug("Flushing cache entry %d\n", entry_index);

	if (write_disk(swap->cache + (entry_index * 4096), entry->disk_index, 4096, swap) == -1) {
	    PrintError("Error in disk write\n");
	    return -1;
	}

	
	if (swap->symbiotic == 1) {
	    v3_swap_in_notify(swap->vm, entry->disk_index / 4096, swap->hdr.info.type);
	}	    
	
	// invalidate swap entry


	v3_htable_remove(swap->entry_ht, entry->disk_index, 0);

	list_move(&(entry->cache_node), &(swap->free_list));

	swap->pages_in_cache--;
    }

    return 0;
}








static int buf_write(uint8_t * buf,  uint64_t lba, uint64_t num_bytes, void * private_data) {
    struct swap_state * swap = (struct swap_state *)private_data;
    uint32_t offset = lba;
    uint32_t length = num_bytes;

    swap->io_flag = 0;



    if (swap->disabled) {
	return write_disk(buf, lba, num_bytes, swap);
    }


    /*
      PrintDebug("SymSwap: Writing %d bytes to %p from %p\n", length, 
      (void *)(swap->swap_space + offset), buf);
    */


    if ((swap->active == 0) && (offset == 0)) {
	// This is the swap header page

	swap->active = 1;

	// store a local copy
	memcpy(&(swap->hdr), buf, sizeof(union swap_header));


	PrintError("Swap Type=%d (magic=%s)\n", swap->hdr.info.type, swap->hdr.magic.magic);

	if (swap->symbiotic == 1) {
	    if (v3_register_swap_disk(swap->vm, swap->hdr.info.type, &swap_ops, swap) == -1) {
		PrintError("Error registering symbiotic swap disk\n");
		return -1;
	    }

	    PrintError("Swap disk registered\n");
	}


	if (write_disk(buf, lba, num_bytes, swap) == -1) {
	    PrintError("Error writing swap header to disk\n");
	    return -1;
	}

	PrintDebug("Wrote header to disk\n");

	return 0;
    }

    if ((swap->active == 1) && (offset >= 4096)) {
	int i = 0;
	int written_pages = (length / 4096);
	int avail_space = (swap->cache_size / 4096) - swap->pages_in_cache;


	swap->swapped_pages += written_pages;
	
#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY
	swap->pages_out += length / 4096;
#endif

	PrintDebug("available cache space = %d, pages written = %d\n", avail_space, written_pages);

	if (avail_space < written_pages) {
	    flush_cache(swap, written_pages - avail_space);
	}
	

	for (i = 0; i < written_pages; i += 1) {
	    //	    set_index_usage(swap, get_swap_index_from_offset(offset + i), 1);
	    struct cache_entry * new_entry = NULL;
	    uint32_t swap_index = offset + (i * 4096);
	    uint32_t cache_index = 0;

	    new_entry = (struct cache_entry *)v3_htable_search(swap->entry_ht, (addr_t)swap_index);

	    if (new_entry == NULL) {
		new_entry = list_tail_entry(&(swap->free_list), struct cache_entry, cache_node);

		new_entry->disk_index = swap_index;

		list_move_tail(&(new_entry->cache_node), &(swap->entry_list));

		v3_htable_insert(swap->entry_ht, (addr_t)swap_index, (addr_t)new_entry);

		swap->pages_in_cache++;
	    }
	    
	    cache_index = get_cache_entry_index(swap, new_entry);
	    
	    PrintDebug("Writing to cache entry %d\n", cache_index);

	    memcpy(swap->cache + (cache_index * 4096), buf, 4096);

	    buf += 4096;
	}
    } else {
	if (write_disk(buf, lba, num_bytes, swap) == -1) {
	    PrintError("Error writing swap header to disk\n");
	    return -1;
	}
    }

    return 0;
}




static uint8_t write_buf[4096];


static int swap_write(uint8_t * buf,  uint64_t lba, uint64_t num_bytes, void * private_data) {
    int idx = lba % 4096;

    if (num_bytes != 512) {
	PrintError("Write for %d bytes\n", (uint32_t)num_bytes);
	return -1;
    }

    
    memcpy(write_buf + idx, buf, num_bytes);

    if (idx + num_bytes == 4096) {
	return buf_write(write_buf, lba - idx, 4096, private_data);
    }

    return 0;
}



static uint8_t read_buf[4096];



static int swap_read(uint8_t * buf,  uint64_t lba, uint64_t num_bytes, void * private_data) {
    int idx = lba % 4096;
    

    if (num_bytes != 512) {
	PrintError("Read for %d bytes\n", (uint32_t)num_bytes);
	return -1;
    }

    if (idx == 0) {
	if (buf_read(read_buf, lba - idx, 4096, private_data) == -1) {
	    PrintError("Error reading buffer\n");
	    return -1;
	}
    }

    memcpy(buf, read_buf + idx, num_bytes);
	
    return 0;
}


static int swap_free(struct vm_device * dev) {
    return -1;
}


static struct v3_dev_blk_ops blk_ops = {
    .read = swap_read, 
    .write = swap_write, 
    .get_capacity = swap_get_capacity,
};



static struct v3_device_ops dev_ops = {
    .free = swap_free,
    .reset = NULL,
    .start = NULL,
    .stop = NULL,
};


#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY
static void telemetry_cb(struct guest_info * info, void * private_data, char * hdr) {
    struct swap_state * swap = (struct swap_state *)private_data;

    V3_Print("%sSwap Device:\n", hdr);
    V3_Print("%s\tPages Swapped in=%d\n", hdr, swap->pages_in);
    V3_Print("%s\tPages Swapped out=%d\n", hdr, swap->pages_out);
    V3_Print("%s\tPages Written to Disk=%d\n", hdr, swap->disk_writes);
    V3_Print("%s\tPages Read from Disk=%d\n", hdr, swap->disk_reads);
}
#endif


static int connect_fn(struct guest_info * info, 
		      void * frontend_data, 
		      struct v3_dev_blk_ops * ops, 
		      v3_cfg_tree_t * cfg, 
		      void * private_data) {
    v3_cfg_tree_t * frontend_cfg = v3_cfg_subtree(cfg, "frontend");
    uint32_t cache_size = atoi(v3_cfg_val(cfg, "cache_size")) * 1024 * 1024;
    uint32_t seek_us = atoi(v3_cfg_val(cfg, "seek_us"));
    int symbiotic = atoi(v3_cfg_val(cfg, "symbiotic"));
    struct swap_state * swap = NULL;
    int i;

    if (!frontend_cfg) {
	PrintError("Initializing sym swap without a frontend device\n");
	return -1;
    }

    PrintError("Creating Swap filter (cache size=%dMB)\n", cache_size / (1024 * 1024));

    swap = (struct swap_state *)V3_Malloc(sizeof(struct swap_state));

    swap->vm = info;
    swap->cache_size = cache_size;
    swap->io_flag = 0;
    swap->seek_usecs = seek_us;
    swap->symbiotic = symbiotic;

    swap->ops = ops;
    swap->private_data = private_data;

    swap->swapped_pages = 0;
    swap->unswapped_pages = 0;
    //    swap->cached_pages = 0;

    if (cache_size == 0) {
	swap->disabled = 1;
    } else {
	swap->disabled = 0;

	INIT_LIST_HEAD(&(swap->entry_list));
	INIT_LIST_HEAD(&(swap->free_list));
	swap->entry_map = (struct cache_entry *)V3_Malloc(sizeof(struct cache_entry) * (cache_size / 4096));
	
	for (i = 0; i < (cache_size / 4096); i++) {
	    list_add(&(swap->entry_map[i].cache_node), &(swap->free_list));
	}

	swap->entry_ht = v3_create_htable(0, cache_hash_fn, cache_eq_fn);

	swap->active = 0;

	swap->cache_base_addr = (addr_t)V3_AllocPages(swap->cache_size / 4096);
	swap->cache = (uint8_t *)V3_VAddr((void *)(swap->cache_base_addr));
	memset(swap->cache, 0, swap->cache_size);
    }

    if (v3_dev_connect_blk(info, v3_cfg_val(frontend_cfg, "tag"), 
			   &blk_ops, frontend_cfg, swap) == -1) {
	PrintError("Could not connect to frontend %s\n", 
		    v3_cfg_val(frontend_cfg, "tag"));
	return -1;
    }


#ifdef CONFIG_SYMBIOTIC_SWAP_TELEMETRY

    if (info->enable_telemetry == 1) {
	v3_add_telemetry_cb(info, telemetry_cb, swap);
    }
    
#endif

    return 0;
}




static int swap_init(struct guest_info * vm, v3_cfg_tree_t * cfg) {

    char * name = v3_cfg_val(cfg, "name");

    struct vm_device * dev = v3_allocate_device(name, &dev_ops, NULL);

    if (v3_attach_device(vm, dev) == -1) {
	PrintError("Could not attach device %s\n", name);
	return -1;
    }

    if (v3_dev_add_blk_frontend(vm, name, connect_fn, NULL) == -1) {
	PrintError("Could not register %s as block frontend\n", name);
	return -1;
    }


    return 0;
}

device_register("SWAPCACHE", swap_init)
