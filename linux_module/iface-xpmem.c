/*
 * Palacios XPMEM host interface 
 * (c) Brian Kocoloski, 2014
 */

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>

#include <xpmem_iface.h>

#include "palacios.h"
#include "vm.h"
#include "mm.h"
#include "linux-exts.h"

#define sint64_t int64_t
#include <interfaces/vmm_xpmem.h>


struct host_xpmem_state {
    /* Guest pointer */
    struct v3_guest       * guest;

    /* Pointer to internal Palacios state */
    struct v3_xpmem_state * v3_xpmem;

    /* XPMEM connection link */
    xpmem_link_t            link;
}; 


static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd,
             void                * priv_data)
{
    struct host_xpmem_state * state    = (struct host_xpmem_state *)priv_data;
    struct v3_xpmem_state   * v3_state = state->v3_xpmem;
    
    return V3_xpmem_command(v3_state, cmd);
}

static int
xpmem_irq_fn(int    irq,
             void * priv_data)
{
    /*
    struct host_xpmem_state * state    = (struct host_xpmem_state *)priv_data;
    struct v3_xpmem_state   * v3_state = state->v3_xpmem;

    return V3_xpmem_raise_irq(v3_state, xpmem_irq_to_vector(irq));
    */
    return 0;
}

static void
xpmem_kill_fn(void * priv_data)
{
    struct host_xpmem_state * state = (struct host_xpmem_state *)priv_data;

    palacios_kfree(state);
}

static xpmem_link_t
palacios_xpmem_host_connect(void                  * private_data, 
	                    struct v3_xpmem_state * v3_xpmem)
{    
    struct v3_guest         * guest = (struct v3_guest *)private_data;
    struct host_xpmem_state * state = NULL;

    if (!guest) {
	ERROR("XPMEM: cannot initialize host channel for NULL guest\n");
	return -1;
    }

    state = get_vm_ext_data(guest, "XPMEM_INTERFACE");
    if (!state) {
	ERROR("XPMEM: cannot locate host state for guest extension XPMEM_INTERFACE\n");
	return -1;
    }

    state->v3_xpmem = v3_xpmem;

    v3_lnx_printk("Guest %s initialized XPMEM host channel\n", guest->name);

    return state->link;
}

static int
palacios_xpmem_host_disconnect(xpmem_link_t link)
{
    struct host_xpmem_state * state = NULL;
    
    state = xpmem_get_link_data(link);
    if (state == NULL) {
	ERROR("XPMEM: Cannot get state for link %d\n", link);
	return -1;
    }

    if (!state->guest) {
	xpmem_put_link_data(state->link);
	ERROR("XPMEM: Cannot disconnect NULL guest\n");
	return -1;
    }

    xpmem_put_link_data(state->link);

    /* Remove the connection now to prevent a race between the guest deinit and another
     * incoming command
     */
    xpmem_remove_connection(state->link);

    return 0;
}


static int
palacios_xpmem_command(xpmem_link_t          link, 
                       struct xpmem_cmd_ex * cmd)		       
{
    struct host_xpmem_state * state = NULL;
    int                       ret   = 0;
    
    state = xpmem_get_link_data(link);
    if (state == NULL) {
	ERROR("XPMEM: Cannot deliver command for link %d\n", link);
	return -1;
    }

    ret = xpmem_cmd_deliver(state->link, cmd);

    xpmem_put_link_data(link);
    return ret;
}

static struct v3_xpmem_hooks 
palacios_xpmem_hooks = 
{
    .xpmem_host_connect    = palacios_xpmem_host_connect,
    .xpmem_host_disconnect = palacios_xpmem_host_disconnect,
    .xpmem_command         = palacios_xpmem_command,
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

    state = palacios_kmalloc(sizeof(struct host_xpmem_state), GFP_KERNEL);
    if (!state) {
	ERROR("XPMEM: out of memory\n");
	return -1;
    }

    state->link = xpmem_add_connection(
	    (void *)state,
	    xpmem_cmd_fn,
	    xpmem_irq_fn,
	    xpmem_kill_fn);
 
    if (state->link <= 0) {
	ERROR("XPMEM: cannot create XPMEM connection\n");
	palacios_kfree(state);
	return -1;
    }

    state->guest     = guest;
    state->v3_xpmem  = NULL;
    *vm_data         = state;

    return 0;
}

static struct linux_ext xpmem_ext = {
    .name         = "XPMEM_INTERFACE",
    .init         = init_xpmem,
    .deinit       = NULL,
    .guest_init   = init_xpmem_guest,
    .guest_deinit = NULL,
};

register_extension(&xpmem_ext);
