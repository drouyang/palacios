/*
 * Palacios XPMEM host interface 
 * (c) Brian Kocoloski, 2014
 */

#include <lwk/list.h>

#include <xpmem_iface.h>

#include "palacios.h"
#include "vm.h"
#include "kitten-exts.h"

#define sint64_t int64_t
#include <interfaces/vmm_xpmem.h>


struct host_xpmem_state {
    /* Guest pointer */
    struct v3_guest              * guest;

    /* Pointer to internal Palacios state */
    struct v3_xpmem_state        * v3_xpmem;
    int                            connected;

    /* XPMEM kernel interface */
    xpmem_link_t                   link;
    struct xpmem_partition_state * part;
}; 


static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd,
             void                * priv_data)
{
    struct host_xpmem_state * state    = (struct host_xpmem_state *)priv_data;
    struct v3_xpmem_state   * v3_state = state->v3_xpmem;

    if (state->connected == 0) {
	return -1;
    }

    return V3_xpmem_command(v3_state, cmd);
}

static void * 
palacios_xpmem_host_connect(void                  * private_data, 
	                    struct v3_xpmem_state * v3_xpmem)
{    
    struct v3_guest         * guest = (struct v3_guest *)private_data;
    struct host_xpmem_state * state = NULL;

    if (!guest) {
	ERROR("XPMEM: cannot initialize host channel for NULL guest\n");
	return NULL;
    }

    state = get_vm_ext_data(guest, "XPMEM_INTERFACE");
    if (!state) {
	ERROR("XPMEM: cannot locate host state for guest extension XPMEM_INTERFACE\n");
	return NULL;
    }

    state->v3_xpmem  = v3_xpmem;
    state->connected = 1;

    printk("Guest initialized XPMEM host channel (Guest=%s)\n", guest->name);

    return state;

}

static int
palacios_xpmem_host_disconnect(void * private_data)
{
    struct host_xpmem_state * state = (struct host_xpmem_state *)private_data;

    if (!state->guest) {
	ERROR("XPMEM: Cannot disconnect NULL guest\n");
	return -1;
    }

    if (!state->connected) {
	ERROR("XPMEM: Cannot disconnect already disconnected guest\n");
	return -1;
    }

    state->v3_xpmem  = NULL;
    state->connected = 0;

    return 0;
}


static int
palacios_xpmem_command(void                * private_data, 
                       struct xpmem_cmd_ex * cmd)		       
{
    struct host_xpmem_state * state = (struct host_xpmem_state *)private_data;

    if (!state->connected) {
	ERROR("XPMEM: cannot process command: not connected to host channel\n");
	return -1;
    }

    return xpmem_cmd_deliver(state->part, state->link, cmd);
}

static struct v3_xpmem_hooks 
palacios_xpmem_hooks = 
{
    .xpmem_host_connect     = palacios_xpmem_host_connect,
    .xpmem_host_disconnect  = palacios_xpmem_host_disconnect,
    .xpmem_command          = palacios_xpmem_command,
};



static int 
init_xpmem(void)
{
    V3_Init_Xpmem(&palacios_xpmem_hooks);
    return 0;
}


static int 
init_xpmem_guest(struct v3_guest * guest, 
                 void           ** vm_data)
{
    struct host_xpmem_state * state = NULL;

    state = kmem_alloc(sizeof(struct host_xpmem_state));
    if (!state) {
	ERROR("XPMEM: out of memory\n");
	return -1;
    }

    state->part = xpmem_get_partition();
    if (!state->part) {
	ERROR("XPMEM: cannot retrieve local XPMEM partition\n");
	kmem_free(state);
	return -1;
    }

    state->link = xpmem_add_connection(
	    state->part,
	    XPMEM_CONN_REMOTE,
	    xpmem_cmd_fn,
	    state);
 
    if (state->link <= 0) {
	ERROR("XPMEM: cannot create XPMEM connection\n");
	kmem_free(state);
	return -1;
    }

    state->guest     = guest;
    state->v3_xpmem  = NULL;
    state->connected = 0;

    *vm_data         = state;

    return 0;
}

static int
deinit_xpmem_guest(struct v3_guest * guest,
                   void            * vm_data)
{
    struct host_xpmem_state * state = (struct host_xpmem_state *)vm_data;

    if (!state->part) {
	ERROR("XPMEM: cannot remove XPMEM connection for NULL partition\n");
	return -1;
    }

    if (xpmem_remove_connection(state->part, state->link) != 0) {
	ERROR("XPMEM: failed to remove XPMEM connection\n");
	return -1;
    }

    kmem_free(state);

    return 0;
}


static struct kitten_ext xpmem_ext = {
    .name         = "XPMEM_INTERFACE",
    .init         = init_xpmem,
    .deinit       = NULL,
    .guest_init   = init_xpmem_guest,
    .guest_deinit = deinit_xpmem_guest,
};

register_extension(&xpmem_ext);
