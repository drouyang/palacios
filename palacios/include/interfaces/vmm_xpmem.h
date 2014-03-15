/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2014, Brian Kocoloski <briankoco@cs.pitt.edu>
 * Copyright (c) 2014, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#ifndef __VMM_XPMEM_H__
#define __VMM_XPMEM_H__

#include <palacios/vmm.h>
#include <palacios/vmm_types.h>

/* Opaque handle to host xpmem state */
typedef void * xpmem_host_handle_t;


struct xpmem_make_cmd {
    sint64_t segid; /* Input/Output - nameserver must ensure uniqueness */
};

struct xpmem_remove_cmd {
    sint64_t segid;
};

struct xpmem_get_cmd {
    sint64_t segid;
    uint32_t flags;
    uint32_t permit_type;
    uint64_t permit_value;
    sint64_t apid; /* Output */
};

struct xpmem_release_cmd {
    sint64_t apid;
};

struct xpmem_attach_cmd {
    sint64_t apid;
    uint64_t off;
    uint64_t size;
    uint64_t num_pfns;
    uint64_t * pfns;
};

struct xpmem_detach_cmd {
    uint64_t vaddr;
};

typedef enum {
    XPMEM_MAKE,
    XPMEM_MAKE_COMPLETE,
    XPMEM_REMOVE,
    XPMEM_REMOVE_COMPLETE,
    XPMEM_GET,
    XPMEM_GET_COMPLETE,
    XPMEM_RELEASE,
    XPMEM_RELEASE_COMPLETE,
    XPMEM_ATTACH,
    XPMEM_ATTACH_COMPLETE,
    XPMEM_DETACH,
    XPMEM_DETACH_COMPLETE,
} xpmem_op_t;

struct xpmem_cmd {
    xpmem_op_t type;
    union {
        struct xpmem_make_cmd make;
        struct xpmem_remove_cmd remove;
        struct xpmem_get_cmd get;
        struct xpmem_release_cmd release;
        struct xpmem_attach_cmd attach;
        struct xpmem_detach_cmd detach;
    };
};

struct v3_xpmem_state;

struct v3_xpmem_hooks {
    xpmem_host_handle_t (*xpmem_host_connect)(void * private_data, struct v3_xpmem_state * v3_xpmem);
    int (*xpmem_host_disconnect)(xpmem_host_handle_t handle);
    int (*xpmem_command)(xpmem_host_handle_t handle, struct xpmem_cmd * cmd);
    int (*xpmem_command_complete)(xpmem_host_handle_t handle, struct xpmem_cmd * cmd);
};




/* Host --> VMM interface */
void V3_Init_Xpmem(struct v3_xpmem_hooks * hooks);

// Incoming command requests/responses
int V3_xpmem_command(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd * cmd);


/* VMM --> Host interface */
xpmem_host_handle_t v3_xpmem_host_connect(struct v3_vm_info * vm, struct v3_xpmem_state * v3_xpmem);
int v3_xpmem_host_disconnect(xpmem_host_handle_t handle);

// Outgoing command requests/responses
int v3_xpmem_host_command(xpmem_host_handle_t handle, struct xpmem_cmd * cmd);

#endif
