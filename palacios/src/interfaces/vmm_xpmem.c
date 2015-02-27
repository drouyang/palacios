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


#include <interfaces/vmm_xpmem.h>
#include <palacios/vmm.h>
#include <palacios/vmm_types.h>
#include <palacios/vm.h>
#include <devices/xpmem.h>

static struct v3_xpmem_hooks * xpmem_hooks = NULL;

void 
V3_Init_Xpmem(struct v3_xpmem_hooks * hooks)
{
    xpmem_hooks = hooks;
}

int 
V3_xpmem_command(struct v3_xpmem_state * v3_xpmem, 
                 struct xpmem_cmd_ex   * cmd)
{
    return v3_xpmem_command(v3_xpmem, cmd);
}

int 
V3_xpmem_raise_irq(struct v3_xpmem_state * v3_xpmem, 
                   uint16_t                guest_vector)
{
    return v3_xpmem_raise_irq(v3_xpmem, guest_vector);
}


xpmem_host_handle_t 
v3_xpmem_host_connect(struct v3_vm_info     * vm, 
                      struct v3_xpmem_state * v3_xpmem)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_host_connect);

    return xpmem_hooks->xpmem_host_connect(vm->host_priv_data, v3_xpmem);
}

int 
v3_xpmem_host_disconnect(xpmem_host_handle_t handle)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_host_disconnect);

    return xpmem_hooks->xpmem_host_disconnect(handle);
}

int 
v3_xpmem_host_command(xpmem_host_handle_t   handle, 
                      struct xpmem_cmd_ex * cmd)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_command);

    return xpmem_hooks->xpmem_command(handle, cmd);
}

int
v3_xpmem_read_apicid(xpmem_host_handle_t handle,
                     uint32_t            cpu)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_read_apicid);

    return xpmem_hooks->xpmem_read_apicid(handle, cpu);
}


int 
v3_xpmem_request_irq(xpmem_host_handle_t handle, 
                     uint16_t            guest_vector)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_request_irq);

    return xpmem_hooks->xpmem_request_irq(handle, guest_vector);
}

int
v3_xpmem_release_irq(xpmem_host_handle_t handle,
                     uint16_t            host_vector)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_release_irq);

    return xpmem_hooks->xpmem_release_irq(handle, host_vector);
}

void
v3_xpmem_deliver_irq(xpmem_host_handle_t handle,
                     xpmem_segid_t       segid,
                     xpmem_sigid_t       sigid,
		     xpmem_domid_t       domid)
{
    V3_ASSERT(xpmem_hooks);
    V3_ASSERT(xpmem_hooks->xpmem_deliver_irq);

    xpmem_hooks->xpmem_deliver_irq(handle, segid, sigid, domid);
}
