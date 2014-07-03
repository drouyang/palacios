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
 *          Mark Cartwright <mcartwright@gmail.com> (live migration)
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __VMM_CHECKPOINT_H__
#define __VMM_CHECKPOINT_H__

#ifdef __V3VEE__




#include <palacios/vmm.h>
#include <palacios/vmm_msr.h>

struct v3_chkpt;


struct v3_chkpt_ctx {
    struct v3_chkpt * chkpt;
    struct v3_chkpt_ctx * parent;
    void * store_ctx;
};




int v3_chkpt_save(struct v3_chkpt_ctx * ctx, char * tag, void * buf, uint64_t len);
int v3_chkpt_load(struct v3_chkpt_ctx * ctx, char * tag, void * buf, uint64_t len);

static inline int v3_chkpt_save_64(struct v3_chkpt_ctx * ctx, char * tag, uint64_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(uint64_t));
}
static inline int v3_chkpt_save_32(struct v3_chkpt_ctx * ctx, char * tag, uint32_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(uint32_t));
}
static inline int v3_chkpt_save_16(struct v3_chkpt_ctx * ctx, char * tag, uint16_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(uint16_t));
}
static inline int v3_chkpt_save_8(struct v3_chkpt_ctx * ctx, char * tag, uint8_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(uint8_t));
}
static inline int v3_chkpt_save_enum(struct v3_chkpt_ctx * ctx, char * tag, void * val, uint32_t size) {
    return v3_chkpt_save(ctx, tag, val, size);
} 
static inline int v3_chkpt_save_ptr(struct v3_chkpt_ctx * ctx, char * tag, addr_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(addr_t));
}
static inline int v3_chkpt_save_msr(struct v3_chkpt_ctx * ctx, char * tag, v3_msr_t * val) {
    return v3_chkpt_save(ctx, tag, val, sizeof(v3_msr_t));
}


static inline int v3_chkpt_load_64(struct v3_chkpt_ctx * ctx, char * tag, uint64_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(uint64_t));
}
static inline int v3_chkpt_load_32(struct v3_chkpt_ctx * ctx, char * tag, uint32_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(uint32_t));
}
static inline int v3_chkpt_load_16(struct v3_chkpt_ctx * ctx, char * tag, uint16_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(uint16_t));
}
static inline int v3_chkpt_load_8(struct v3_chkpt_ctx * ctx, char * tag, uint8_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(uint8_t));
}
static inline int v3_chkpt_load_enum(struct v3_chkpt_ctx * ctx, char * tag, void * val, uint32_t size) {
    return v3_chkpt_load(ctx, tag, val, size);
} 
static inline int v3_chkpt_load_ptr(struct v3_chkpt_ctx * ctx, char * tag, addr_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(addr_t));
} 
static inline int v3_chkpt_load_msr(struct v3_chkpt_ctx * ctx, char * tag, v3_msr_t * val) {
    return v3_chkpt_load(ctx, tag, val, sizeof(v3_msr_t));
} 



int v3_chkpt_close_ctx(struct v3_chkpt_ctx * ctx);
struct v3_chkpt_ctx * v3_chkpt_open_ctx(struct v3_chkpt * chkpt, struct v3_chkpt_ctx * parent, char * name);

int v3_chkpt_save_vm(struct v3_vm_info * vm, char * store, char * url);
int v3_chkpt_load_vm(struct v3_vm_info * vm, char * store, char * url);

#ifdef V3_CONFIG_LIVE_MIGRATION
int v3_chkpt_send_vm(struct v3_vm_info * vm, char * store, char * url);
int v3_chkpt_receive_vm(struct v3_vm_info * vm, char * store, char * url);
#endif

int V3_init_checkpoint();
int V3_deinit_checkpoint();

#endif

#endif
