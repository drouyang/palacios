/*
 * Copyright (c) 2014, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __VMM_CHECKPOINT_H__
#define __VMM_CHECKPOINT_H__

#ifdef __V3VEE__


struct v3_chkpt_state {

    struct list_head   block_list;
    struct hashtable * block_table;

    uint32_t  num_blocks;
    size_t    block_size;
};


#include <palacios/vmm.h>
#include <palacios/vmm_msr.h>

typedef int (*v3_chkpt_save_fn)(char * name, void * buf, size_t size, void * priv_data);
typedef int (*v3_chkpt_load_fn)(char * name, void * buf, size_t size, void * priv_data);



int v3_checkpoint_register(struct v3_vm_info * vm, char * name, v3_chkpt_save_fn save, v3_chkpt_load_fn load, size_t size, void * priv_data);
int v3_checkpoint_register_nocopy(struct v3_vm_info * vm, char * name, uint8_t * buf, size_t size);

int v3_chkpt_save_vm(struct v3_vm_info * vm, char * store, char * url);
int v3_chkpt_load_vm(struct v3_vm_info * vm, char * store, char * url);

int v3_init_chkpt(struct v3_vm_info * vm);
int v3_deinit_chkpt(struct v3_vm_info * vm);


int V3_init_chkpt_stores();
int V3_deinit_chkpt_stores();


#endif

#endif
