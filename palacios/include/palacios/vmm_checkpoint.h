/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2011, Madhav Suresh <madhav@u.northwestern.edu> 
 * Copyright (c) 2011, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Authors: Madhav Suresh <madhav@u.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __VMM_CHECKPOINT_H__
#define __VMM_CHECKPOINT_H__

#ifdef __V3VEE__


struct v3_chkpt_state {

    struct list_head handler_list; 

    uint32_t  num_handlers;
    size_t    chkpt_tot_size;
    size_t    chkpt_buf_size;
    uint8_t * chkpt_buf;


};


#include <palacios/vmm.h>
#include <palacios/vmm_msr.h>



typedef int (*v3_chkpt_save_fn)(char * name, void * buf, size_t size, void * priv_data);
typedef int (*v3_chkpt_load_fn)(char * name, void * buf, size_t size, void * priv_data);


int v3_chkpt_register(struct v3_vm_info * vm, char * name, v3_chkpt_save_fn save, v3_chkpt_load_fn load, size_t size);


#define DECLARE_CHECKPOINT(vm, name, save, load, data_type) v3_chkpt_register(vm, name, save, load, sizeof(data_type));




struct v3_chkpt_ctx {
    struct v3_chkpt * chkpt;
    struct v3_chkpt_ctx * parent;
    void * store_ctx;
};


int v3_chkpt_save(struct v3_chkpt_ctx * ctx, char * tag, void * buf, uint64_t len);
int v3_chkpt_load(struct v3_chkpt_ctx * ctx, char * tag, void * buf, uint64_t len);




int v3_chkpt_close_ctx(struct v3_chkpt_ctx * ctx);
struct v3_chkpt_ctx * v3_chkpt_open_ctx(struct v3_chkpt * chkpt, struct v3_chkpt_ctx * parent, char * name);

int v3_chkpt_save_vm(struct v3_vm_info * vm, char * store, char * url);
int v3_chkpt_load_vm(struct v3_vm_info * vm, char * store, char * url);

int V3_init_checkpoint();
int V3_deinit_checkpoint();

#endif

#endif
