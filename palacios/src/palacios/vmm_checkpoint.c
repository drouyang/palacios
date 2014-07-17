/* 
 * Copyright (c) 2014, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_sprintf.h>
#include <palacios/vm.h>
#include <palacios/svm.h>
#include <palacios/vmx.h>
#include <palacios/vmm_checkpoint.h>
#include <palacios/vmm_hashtable.h>
#include <palacios/vmm_direct_paging.h>
#include <palacios/vmm_debug.h>
#include <palacios/vmm_mem.h>

#include <palacios/vmm_dev_mgr.h>

#ifdef V3_CONFIG_LIVE_MIGRATION
#include <palacios/vmm_time.h>
#include <palacios/vm_guest_mem.h>
#include <palacios/vmm_shadow_paging.h>
#endif

#ifndef V3_CONFIG_DEBUG_CHECKPOINT
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

#define CHKPT_KEY_LEN   32
#define HEADER_BUF_SIZE 32

static struct hashtable * store_table   = NULL;

struct v3_chkpt;

typedef enum {SAVE, LOAD} chkpt_mode_t;

struct chkpt_block {
    char name[CHKPT_KEY_LEN];

    v3_chkpt_save_fn save;
    v3_chkpt_load_fn load;

    void * priv;

    union {
	uint32_t flags;
	struct {
	    uint32_t   zero_copy : 1;
	    uint32_t   rsvd      : 31;
	} __attribute__((packed));
    } __attribute__((packed));

    size_t    size;
    uint8_t * block_ptr;

    struct list_head node;
};


struct chkpt_interface {
    char name[CHKPT_KEY_LEN];

    void * (*open_chkpt)(struct v3_vm_info * vm, char * url, chkpt_mode_t mode);
    int    (*close_chkpt)(void * store_data);
    
    int    (*save_block)(struct chkpt_block * block, void * store_data);
    int    (*load_block)(struct chkpt_block * block, void * store_data);
};




struct v3_chkpt {
    struct v3_vm_info      * vm;
    struct chkpt_interface * interface;
    void                   * store_data;
};


static uint_t key_hash_fn(addr_t key) {
    char     * name     = (char *)key;
    uint32_t   name_len = (strlen(name) > CHKPT_KEY_LEN) ? CHKPT_KEY_LEN : strlen(name); 

    return v3_hash_buffer((uint8_t *)name, name_len);
}

static int key_eq_fn(addr_t key1, addr_t key2) {
    char * name1 = (char *)key1;
    char * name2 = (char *)key2;

    return (strncmp(name1, name2, CHKPT_KEY_LEN - 1) == 0);
}



#include "vmm_chkpt_stores.h"


int 
V3_init_chkpt_stores() 
{
    extern struct chkpt_interface  * __start__v3_chkpt_stores[];
    extern struct chkpt_interface  * __stop__v3_chkpt_stores[];

    struct chkpt_interface        ** tmp_store = __start__v3_chkpt_stores;
    int i = 0;

    store_table = v3_create_htable(0, key_hash_fn, key_eq_fn);

    while (tmp_store != __stop__v3_chkpt_stores) {
	V3_Print("Registering Checkpoint Backing Store (%s)\n", (*tmp_store)->name);

	if (v3_htable_search(store_table, (addr_t)((*tmp_store)->name))) {
	    PrintError("Multiple instances of Checkpoint backing Store (%s)\n", (*tmp_store)->name);
	    return -1;
	}

	if (v3_htable_insert(store_table, (addr_t)((*tmp_store)->name), (addr_t)(*tmp_store)) == 0) {
	    PrintError("Could not register Checkpoint backing store (%s)\n", (*tmp_store)->name);
	    return -1;
	}

	tmp_store = &(__start__v3_chkpt_stores[++i]);
    }

    return 0;
}


int
V3_deinit_chkpt_stores()
{

    v3_free_htable(store_table, 0, 0);
    return 0;
}


static char svm_chkpt_header[] = "v3-checkpoint: SVM";
static char vmx_chkpt_header[] = "v3-checkpoint: VMX";


static int 
header_save(char   * name, 
	    void   * buf, 
	    size_t   size,
	    void   * priv_data)
{
    extern v3_cpu_arch_t v3_mach_type;
    
    if ((size != HEADER_BUF_SIZE) ||
	(strncmp(name, "HEADER", strlen("HEADER")) != 0)) {
	PrintError("Attempting to save invalid checkpoint header\n");
	return -1;
    }

    switch (v3_mach_type) {
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	    strncpy(buf, svm_chkpt_header, HEADER_BUF_SIZE - 1);
	    break;
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:
	    strncpy(buf, vmx_chkpt_header, HEADER_BUF_SIZE - 1);
	    break;
	default:
	    PrintError("checkpoint not supported on this architecture\n");
	    return -1;
    }
    
    return 0;
}

static int 
header_load(char   * name, 
	    void   * buf, 
	    size_t   size,
	    void   * priv_data)
{
    extern v3_cpu_arch_t v3_mach_type;
 

    if ((size != HEADER_BUF_SIZE) ||
	(strncmp(name, "HEADER", strlen("HEADER")) != 0)) {
	PrintError("Attempting to save invalid checkpoint header\n");
	return -1;
    } 

    switch (v3_mach_type) {
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	 
	    if (strncmp(buf, svm_chkpt_header, HEADER_BUF_SIZE - 1) != 0) {
		PrintError("Invalid header (%s) [expected (%s)]\n", (char *)buf, svm_chkpt_header);
		return -1;
	    }

	    break;
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:

	    if (strncmp(buf, vmx_chkpt_header, HEADER_BUF_SIZE - 1) != 0) {
		PrintError("Invalid header (%s) [expected (%s)]\n", (char *)buf, vmx_chkpt_header);
		return -1;
	    }	    

	    break;
	default:
	    PrintError("checkpoint not supported on this architecture\n");
	    return -1;
    }
    
    return 0;
}




int 
v3_init_chkpt(struct v3_vm_info * vm)
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);
    
    INIT_LIST_HEAD(&(chkpt_state->block_list));

    chkpt_state->block_table = v3_create_htable(0, key_hash_fn, key_eq_fn);

    chkpt_state->num_blocks  = 0;
    chkpt_state->block_size  = 0;

    v3_checkpoint_register(vm, "HEADER", header_save, header_load, HEADER_BUF_SIZE, NULL);

    return 0;
}

int
v3_deinit_chkpt(struct v3_vm_info * vm)
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);

    struct chkpt_block * block = NULL;
    struct chkpt_block * tmp   = NULL;

    list_for_each_entry_safe(block, tmp, &(chkpt_state->block_list), node) {
	list_del(&(block->node));
	V3_Free(block);
    }

    v3_free_htable(chkpt_state->block_table, 0, 0);

    return 0;
}


int 
v3_checkpoint_register(struct v3_vm_info * vm, 
		       char              * name, 
		       v3_chkpt_save_fn    save, 
		       v3_chkpt_load_fn    load, 
		       size_t              size, 
		       void              * priv_data) 
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);
    struct chkpt_block    * block       = NULL;


    if (v3_htable_search(chkpt_state->block_table, (addr_t)name)) {
	PrintError("Chkpt block already registered with name: (%s)\n", name);
	return -1;
    }


    block = V3_Malloc(sizeof(struct chkpt_block));
    
    if (block == NULL) {
	PrintError("Could not allocate chkpt block of size %lu for (%s)\n", size, name);
	return -1;
    }

    memset(block, 0, sizeof(struct chkpt_block));

    strncpy(block->name, name, CHKPT_KEY_LEN - 1);
    
    block->save = save;
    block->load = load;
    block->size = size;
    block->priv = priv_data;
    
    if (v3_htable_insert(chkpt_state->block_table, (addr_t)block->name, (addr_t)block) == 0) {
	PrintError("Error inserting chkpt block into block table\n");
	V3_Free(block);
	return -1;
    }

    list_add_tail(&(block->node), &(chkpt_state->block_list));
    chkpt_state->num_blocks += 1;
    chkpt_state->block_size += block->size;

    return 0;
}

int 
v3_checkpoint_register_nocopy(struct v3_vm_info * vm, 
			      char              * name, 
			      uint8_t           * buf,
			      size_t              size) 
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);
    struct chkpt_block    * block       = NULL;


    if (v3_htable_search(chkpt_state->block_table, (addr_t)name)) {
	PrintError("Chkpt block already registered with name: (%s)\n", name);
	return -1;
    }


    block = V3_Malloc(sizeof(struct chkpt_block));
    
    if (block == NULL) {
	PrintError("Could not allocate chkpt block of size %lu for (%s)\n", size, name);
	return -1;
    }

    memset(block, 0, sizeof(struct chkpt_block));

    strncpy(block->name, name, CHKPT_KEY_LEN - 1);
    
    block->block_ptr = buf;
    block->zero_copy = 1;
    block->size      = size;
    
    if (v3_htable_insert(chkpt_state->block_table, (addr_t)block->name, (addr_t)block) == 0) {
	PrintError("Error inserting chkpt block into block table\n");
	V3_Free(block);
	return -1;
    }

    list_add_tail(&(block->node), &(chkpt_state->block_list));
    chkpt_state->num_blocks += 1;

    return 0;
}


static int 
chkpt_close(struct v3_chkpt * chkpt) 
{
    chkpt->interface->close_chkpt(chkpt->store_data);

    V3_Free(chkpt);

    return 0;
}


static struct v3_chkpt * 
chkpt_open(struct v3_vm_info * vm,
	   char              * store, 
	   char              * url, 
	   chkpt_mode_t        mode)
{
    struct chkpt_interface * iface      = NULL;
    struct v3_chkpt        * chkpt      = NULL;
    void                   * store_data = NULL;

    iface = (void *)v3_htable_search(store_table, (addr_t)store);
    
    if (iface == NULL) {
	V3_Print("Error: Could not locate Checkpoint interface for store (%s)\n", store);
	return NULL;
    }

    store_data = iface->open_chkpt(vm, url, mode);

    if (store_data == NULL) {
	PrintError("Could not open url (%s) for backing store (%s)\n", url, store);
	return NULL;
    }


    chkpt = V3_Malloc(sizeof(struct v3_chkpt));

    if (!chkpt) {
	PrintError("Could not allocate checkpoint state\n");
	return NULL;
    }

    chkpt->interface  = iface;
    chkpt->vm         = vm;
    chkpt->store_data = store_data;
    
    return chkpt;
}

int 
v3_chkpt_save_vm(struct v3_vm_info * vm, 
		 char              * store, 
		 char              * url)
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);
    struct v3_chkpt       * chkpt       = NULL;
    int ret = 0;
 
    chkpt = chkpt_open(vm, store, url, SAVE);

    if (chkpt == NULL) {
	PrintError("Error creating checkpoint store for url %s\n",url);
	return -1;
    }

    /* If this guest is running we need to block it while the checkpoint occurs */
    if (vm->run_state == VM_RUNNING) {
	while (v3_raise_barrier(vm, NULL) == -1);
    }

    {
	struct chkpt_block * block = NULL;

	list_for_each_entry(block, &(chkpt_state->block_list), node) {
	    ret = chkpt->interface->save_block(block, chkpt->store_data);

	    if (ret == -1) {
		PrintError("Error saving block (%s)\n", block->name);
		goto out;
	    }
	}
    }

 out:
    /* Resume the guest if it was running */
    if (vm->run_state == VM_RUNNING) {
	v3_lower_barrier(vm);
    }

    chkpt_close(chkpt);

    return ret;
}

int 
v3_chkpt_load_vm(struct v3_vm_info * vm,
		 char              * store, 
		 char              * url)
{
    struct v3_chkpt_state * chkpt_state = &(vm->chkpt_state);
    struct v3_chkpt       * chkpt       = NULL;
    int ret = 0;
    
    chkpt = chkpt_open(vm, store, url, LOAD);

    if (chkpt == NULL) {
	PrintError("Error creating checkpoint store\n");
	return -1;
    }

    /* If this guest is running we need to block it while the checkpoint occurs */
    if (vm->run_state == VM_RUNNING) {
	while (v3_raise_barrier(vm, NULL) == -1);
    }

    {
	struct chkpt_block * block = NULL;

	list_for_each_entry(block, &(chkpt_state->block_list), node) {
	    ret = chkpt->interface->load_block(block, chkpt->store_data);

	    if (ret == -1) {
		PrintError("Error saving block (%s)\n", block->name);
		goto out;
	    }
	}
    }

 out:
    /* Resume the guest if it was running and we didn't just trash the state*/
    if (vm->run_state == VM_RUNNING) {
    
	if (ret == -1) {
	    vm->run_state = VM_STOPPED;
	}

	/* We check the run state of the VM after every barrier 
	   So this will immediately halt the VM 
	*/
	v3_lower_barrier(vm);
    }

    chkpt_close(chkpt);

    return ret;
}



























#ifdef V3_CONFIG_LIVE_MIGRATION

struct mem_migration_state {
    struct v3_vm_info *vm;
    struct v3_bitmap  modified_pages; 
};




//
// Returns
//  negative: error
//  zero: done with this round
static int save_inc_memory(struct v3_vm_info * vm, 
                           struct v3_bitmap * mod_pgs_to_send, 
                           struct v3_chkpt * chkpt) {
    int page_size_bytes = 1 << 12; // assuming 4k pages right now
    void * ctx = NULL;
    int i = 0; 
    void * guest_mem_base = NULL;
    int bitmap_num_bytes = (mod_pgs_to_send->num_bits / 8) 
                           + ((mod_pgs_to_send->num_bits % 8) > 0);

   
    guest_mem_base = V3_VAddr((void *)vm->mem_map.base_region.host_addr);
    
    PrintDebug("Saving incremental memory.\n");

    ctx = v3_chkpt_open_ctx(chkpt, NULL,"memory_bitmap_bits");

    if (!ctx) { 
	PrintError("Cannot open context for dirty memory bitmap\n");
	return -1;
    }
	

    if (v3_chkpt_save(ctx,
		      "memory_bitmap_bits",
		      bitmap_num_bytes,
		      mod_pgs_to_send->bits) == -1) {
	PrintError("Unable to write all of the dirty memory bitmap\n");
	v3_chkpt_close_ctx(ctx);
	return -1;
    }

    v3_chkpt_close_ctx(ctx);

    PrintDebug("Sent bitmap bits.\n");

    // Dirty memory pages are sent in bitmap order
    for (i = 0; i < mod_pgs_to_send->num_bits; i++) {
        if (v3_bitmap_check(mod_pgs_to_send, i)) {
           // PrintDebug("Sending memory page %d.\n",i);
            ctx = v3_chkpt_open_ctx(chkpt, NULL,"memory_page");
	    if (!ctx) { 
		PrintError("Unable to open context to send memory page\n");
		return -1;
	    }
            if (v3_chkpt_save(ctx, 
			      "memory_page", 
			      page_size_bytes,
			      guest_mem_base + (page_size_bytes * i)) == -1) {
		PrintError("Unable to send a memory page\n");
		v3_chkpt_close_ctx(ctx);
		return -1;
	    }
	    
            v3_chkpt_close_ctx(ctx);
        }
    } 
    
    return 0;
}


//
// returns:
//  negative: error
//  zero: ok, but not done
//  positive: ok, and also done
static int load_inc_memory(struct v3_vm_info * vm, 
                           struct v3_bitmap * mod_pgs,
                           struct v3_chkpt * chkpt) {
    int page_size_bytes = 1 << 12; // assuming 4k pages right now
    void * ctx = NULL;
    int i = 0; 
    void * guest_mem_base = NULL;
    bool empty_bitmap = true;
    int bitmap_num_bytes = (mod_pgs->num_bits / 8) 
                           + ((mod_pgs->num_bits % 8) > 0);


    guest_mem_base = V3_VAddr((void *)vm->mem_map.base_region.host_addr);

    ctx = v3_chkpt_open_ctx(chkpt, NULL,"memory_bitmap_bits");

    if (!ctx) { 
	PrintError("Cannot open context to receive memory bitmap\n");
	return -1;
    }

    if (v3_chkpt_load(ctx,
		      "memory_bitmap_bits",
		      bitmap_num_bytes,
		      mod_pgs->bits) == -1) {
	PrintError("Did not receive all of memory bitmap\n");
	v3_chkpt_close_ctx(ctx);
	return -1;
    }
    
    v3_chkpt_close_ctx(ctx);

    // Receive also follows bitmap order
    for (i = 0; i < mod_pgs->num_bits; i ++) {
        if (v3_bitmap_check(mod_pgs, i)) {
            PrintDebug("Loading page %d\n", i);
            empty_bitmap = false;
            ctx = v3_chkpt_open_ctx(chkpt, NULL,"memory_page");
	    if (!ctx) { 
		PrintError("Cannot open context to receive memory page\n");
		return -1;
	    }
	    
            if (v3_chkpt_load(ctx, 
			      "memory_page", 
			      page_size_bytes,
			      guest_mem_base + (page_size_bytes * i)) == -1) {
		PrintError("Did not receive all of memory page\n");
		v3_chkpt_close_ctx(ctx);
		return -1;
	    }
            v3_chkpt_close_ctx(ctx);
        }
    }
    
    if (empty_bitmap) {
        // signal end of receiving pages
        PrintDebug("Finished receiving pages.\n");
	return 1;
    } else {
	// need to run again
	return 0;
    }

}


#define MOD_THRESHOLD   200  // pages below which we declare victory
#define ITER_THRESHOLD  32   // iters below which we declare victory



int v3_chkpt_send_vm(struct v3_vm_info * vm, char * store, char * url) {
    struct v3_chkpt * chkpt = NULL;
    int ret = 0;;
    int iter = 0;
    bool last_modpage_iteration=false;
    struct v3_bitmap modified_pages_to_send;
    uint64_t start_time;
    uint64_t stop_time;
    int num_mod_pages=0;
    struct mem_migration_state *mm_state;
    int i;

    // Currently will work only for shadow paging
    for (i=0;i<vm->num_cores;i++) { 
	if (vm->cores[i].shdw_pg_mode!=SHADOW_PAGING) { 
	    PrintError("Cannot currently handle nested paging\n");
	    return -1;
	}
    }
    
    
    chkpt = chkpt_open(vm, store, url, SAVE);
    
    if (chkpt == NULL) {
	PrintError("Error creating checkpoint store\n");
	chkpt_close(chkpt);
	return -1;
    }
    
    // In a send, the memory is copied incrementally first,
    // followed by the remainder of the state
    
    if (v3_bitmap_init(&modified_pages_to_send,
		       vm->mem_size>>12 // number of pages in main region
		       ) == -1) {
        PrintError("Could not intialize bitmap.\n");
        return -1;
    }

    // 0. Initialize bitmap to all 1s
    for (i=0; i < modified_pages_to_send.num_bits; i++) {
        v3_bitmap_set(&modified_pages_to_send,i);
    }

    iter = 0;
    while (!last_modpage_iteration) {
        PrintDebug("Modified memory page iteration %d\n",i++);
        
        start_time = v3_get_host_time(&(vm->cores[0].time_state));
        
	// We will pause the VM for a short while
	// so that we can collect the set of changed pages
        if (v3_pause_vm(vm) == -1) {
            PrintError("Could not pause VM\n");
            ret = -1;
            goto out;
        }
        
	if (iter==0) { 
	    // special case, we already have the pages to send (all of them)
	    // they are already in modified_pages_to_send
	} else {
	    // normally, we are in the middle of a round
	    // We need to copy from the current tracking bitmap
	    // to our send bitmap
	    v3_bitmap_copy(&modified_pages_to_send,&(mm_state->modified_pages));
	    // and now we need to remove our tracking
	    stop_page_tracking(mm_state);
	}

	// are we done? (note that we are still paused)
        num_mod_pages = v3_bitmap_count(&modified_pages_to_send);
	if (num_mod_pages<MOD_THRESHOLD || iter>ITER_THRESHOLD) {
	    // we are done, so we will not restart page tracking
	    // the vm is paused, and so we should be able
	    // to just send the data
            PrintDebug("Last modified memory page iteration.\n");
            last_modpage_iteration = true;
	} else {
	    // we are not done, so we will restart page tracking
	    // to prepare for a second round of pages
	    // we will resume the VM as this happens
	    if (!(mm_state=start_page_tracking(vm))) { 
		PrintError("Error enabling page tracking.\n");
		ret = -1;
		goto out;
	    }
            if (v3_continue_vm(vm) == -1) {
                PrintError("Error resuming the VM\n");
		stop_page_tracking(mm_state);
                ret = -1;
                goto out;
            }
	    
            stop_time = v3_get_host_time(&(vm->cores[0].time_state));
            PrintDebug("num_mod_pages=%d\ndowntime=%llu\n",num_mod_pages,stop_time-start_time);
        }
	

	// At this point, we are either paused and about to copy
	// the last chunk, or we are running, and will copy the last
	// round in parallel with current execution
	if (num_mod_pages>0) { 
	    if (save_inc_memory(vm, &modified_pages_to_send, chkpt) == -1) {
		PrintError("Error sending incremental memory.\n");
		ret = -1;
		goto out;
	    }
	} // we don't want to copy an empty bitmap here
	
	iter++;
    }        
    
    if (v3_bitmap_reset(&modified_pages_to_send) == -1) {
        PrintError("Error reseting bitmap.\n");
        ret = -1;
        goto out;
    }    
    
    // send bitmap of 0s to signal end of modpages
    if (save_inc_memory(vm, &modified_pages_to_send, chkpt) == -1) {
        PrintError("Error sending incremental memory.\n");
        ret = -1;
        goto out;
    }
    
    // save the non-memory state
    if ((ret = v3_save_vm_devices(vm, chkpt)) == -1) {
	PrintError("Unable to save devices\n");
	goto out;
    }
    

    if ((ret = save_header(vm, chkpt)) == -1) {
	PrintError("Unable to save header\n");
	goto out;
    }
    
    for (i = 0; i < vm->num_cores; i++){
	if ((ret = save_core(&(vm->cores[i]), chkpt)) == -1) {
	    PrintError("chkpt of core %d failed\n", i);
	    goto out;
	}
    }
    
    stop_time = v3_get_host_time(&(vm->cores[0].time_state));
    PrintDebug("num_mod_pages=%d\ndowntime=%llu\n",num_mod_pages,stop_time-start_time);
    PrintDebug("Done sending VM!\n"); 
 out:
    v3_bitmap_deinit(&modified_pages_to_send);
    chkpt_close(chkpt);
    
    return ret;

}

int v3_chkpt_receive_vm(struct v3_vm_info * vm, char * store, char * url) {
    struct v3_chkpt * chkpt = NULL;
    int i = 0;
    int ret = 0;
    struct v3_bitmap mod_pgs;
 
    // Currently will work only for shadow paging
    for (i=0;i<vm->num_cores;i++) { 
	if (vm->cores[i].shdw_pg_mode!=SHADOW_PAGING) { 
	    PrintError("Cannot currently handle nested paging\n");
	    return -1;
	}
    }
    
    chkpt = chkpt_open(vm, store, url, LOAD);
    
    if (chkpt == NULL) {
	PrintError("Error creating checkpoint store\n");
	chkpt_close(chkpt);
	return -1;
    }
    
    if (v3_bitmap_init(&mod_pgs,vm->mem_size>>12) == -1) {
	chkpt_close(chkpt);
        PrintError("Could not intialize bitmap.\n");
        return -1;
    }
    
    /* If this guest is running we need to block it while the checkpoint occurs */
    if (vm->run_state == VM_RUNNING) {
	while (v3_raise_barrier(vm, NULL) == -1);
    }
    
    i = 0;
    while(true) {
        // 1. Receive copy of bitmap
        // 2. Receive pages
        PrintDebug("Memory page iteration %d\n",i++);
        int retval = load_inc_memory(vm, &mod_pgs, chkpt);
        if (retval == 1) {
            // end of receiving memory pages
            break;        
        } else if (retval == -1) {
            PrintError("Error receiving incremental memory.\n");
            ret = -1;
            goto out;
	}
    }        
    
    if ((ret = v3_load_vm_devices(vm, chkpt)) == -1) {
	PrintError("Unable to load devices\n");
	ret = -1;
	goto out;
    }
    
    
    if ((ret = load_header(vm, chkpt)) == -1) {
	PrintError("Unable to load header\n");
	ret = -1;
	goto out;
    }
    
    //per core cloning
    for (i = 0; i < vm->num_cores; i++) {
	if ((ret = load_core(&(vm->cores[i]), chkpt)) == -1) {
	    PrintError("Error loading core state (core=%d)\n", i);
	    goto out;
	}
    }
    
 out:
    if (ret==-1) { 
	PrintError("Unable to receive VM\n");
    } else {
	PrintDebug("Done receving the VM\n");
    }
	
	
    /* Resume the guest if it was running and we didn't just trash the state*/
    if (vm->run_state == VM_RUNNING) { 
	if (ret == -1) {
	    PrintError("VM was previously running.  It is now borked.  Pausing it. \n");
	    vm->run_state = VM_STOPPED;
	}
	    
	/* We check the run state of the VM after every barrier 
	   So this will immediately halt the VM 
	*/
	v3_lower_barrier(vm);
    } 
    
    v3_bitmap_deinit(&mod_pgs);
    chkpt_close(chkpt);

    return ret;
}

#endif
