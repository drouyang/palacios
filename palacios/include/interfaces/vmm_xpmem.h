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

typedef sint64_t xpmem_domid_t;
typedef sint64_t xpmem_sigid_t;
typedef sint64_t xpmem_segid_t;
typedef sint64_t xpmem_apid_t;
typedef signed short xpmem_link_t;

/* Opaque handle to host xpmem state */
typedef xpmem_link_t xpmem_host_handle_t;


struct v3_xpmem_state;
struct xpmem_cmd_ex;

struct v3_xpmem_hooks {
    xpmem_host_handle_t (*xpmem_host_connect)(void * private_data, struct v3_xpmem_state * v3_xpmem);
    int (*xpmem_host_disconnect)(xpmem_host_handle_t handle);
    int (*xpmem_command)(xpmem_host_handle_t handle, struct xpmem_cmd_ex * cmd);
    int (*xpmem_read_apicid)(xpmem_host_handle_t, uint32_t logical_cpu);
    int (*xpmem_request_irq)(xpmem_host_handle_t, uint16_t guest_vector);
    int (*xpmem_release_irq)(xpmem_host_handle_t, uint16_t host_vector);
    void (*xpmem_deliver_irq)(xpmem_host_handle_t, xpmem_segid_t segid, xpmem_sigid_t sigid, xpmem_domid_t domid);
};




/* Host --> VMM interface */
void V3_Init_Xpmem(struct v3_xpmem_hooks * hooks);

// Incoming command requests/responses
int V3_xpmem_command(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd_ex * cmd);
int V3_xpmem_raise_irq(struct v3_xpmem_state * v3_xpmem, uint16_t guest_vector);


/* VMM --> Host interface */
xpmem_host_handle_t v3_xpmem_host_connect(struct v3_vm_info * vm, struct v3_xpmem_state * v3_xpmem);
int v3_xpmem_host_disconnect(xpmem_host_handle_t handle);

// Outgoing command requests/responses
int v3_xpmem_host_command(xpmem_host_handle_t handle, struct xpmem_cmd_ex * cmd);
int v3_xpmem_read_apicid(xpmem_host_handle_t, uint32_t logical_cpu);
int v3_xpmem_request_irq(xpmem_host_handle_t handle, uint16_t guest_vector);
int v3_xpmem_release_irq(xpmem_host_handle_t handle, uint16_t host_vector);
void v3_xpmem_deliver_irq(xpmem_host_handle_t handle, xpmem_segid_t segid, xpmem_sigid_t sigid, xpmem_domid_t domid);

#endif
