/*
 * Palacios XPMEM host interface 
 * (c) Brian Kocoloski, 2014
 */


#include <xpmem_iface.h>
#include <xpmem_extended.h>

#include <asm/ipi.h>

#include "palacios.h"
#include "vm.h"
#include "mm.h"
#include "linux-exts.h"

#define sint64_t int64_t
#include <interfaces/vmm_xpmem.h>



struct xpmem_idt_info {
    int      host_irq;
    uint16_t guest_vector;
    int      in_use;
};

struct host_xpmem_state {
    /* Guest pointer */
    struct v3_guest	  * guest;

    /* Pointer to internal Palacios state */
    struct v3_xpmem_state * v3_xpmem;

    /* XPMEM kernel interface */
    xpmem_link_t            link;

    /* Host vector to guest vector translations */
    rwlock_t                idt_lock;
    struct xpmem_idt_info   idt_map[NR_VECTORS];
}; 


static void
xpmem_set_idt_info(struct host_xpmem_state * state,
                   uint16_t                  host_vector,
		   struct xpmem_idt_info   * info)
{

    write_lock(&(state->idt_lock));
    {
	state->idt_map[host_vector].host_irq     = info->host_irq;
	state->idt_map[host_vector].guest_vector = info->guest_vector;
	state->idt_map[host_vector].in_use       = 1;
    }
    write_unlock(&(state->idt_lock));
}

static int
xpmem_get_idt_info(struct host_xpmem_state * state,
                   uint16_t                  host_vector,
		   struct xpmem_idt_info   * info)
{
    int status = -1;

    read_lock(&(state->idt_lock));
    {
	if (state->idt_map[host_vector].in_use) {
	    info->host_irq     = state->idt_map[host_vector].host_irq;
	    info->guest_vector = state->idt_map[host_vector].guest_vector;

	    status = 0;
	}
    }
    read_unlock(&(state->idt_lock));

    return status;
}

static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd,
             void                * priv_data)
{
    struct host_xpmem_state * state    = (struct host_xpmem_state *)priv_data;
    struct v3_xpmem_state   * v3_state = state->v3_xpmem;
    
    return V3_xpmem_command(v3_state, cmd);
}

static int
xpmem_segid_fn(xpmem_segid_t segid,
               xpmem_sigid_t sigid,
	       xpmem_domid_t domid,
               void        * priv_data)
{
    struct host_xpmem_state * state    = (struct host_xpmem_state *)priv_data;
    struct v3_xpmem_state   * v3_state = state->v3_xpmem;
    struct xpmem_signal     * sig      = (struct xpmem_signal *)&sigid;
    int                       vector   = sig->vector;
    int                       status   = 0;
    struct xpmem_idt_info     info;

    /* Get idt info */
    status = xpmem_get_idt_info(state, vector, &info);
    if (status != 0) {
	ERROR("XPMEM: Cannot get idt info for host vector %d\n", vector);
	return -EINVAL;
    }

    return V3_xpmem_raise_irq(v3_state, info.guest_vector);
}

static irqreturn_t
xpmem_irq_fn(int    irq,
	     void * priv_data)
{
    xpmem_sigid_t         sigid = 0;
    struct xpmem_signal * sig   = (struct xpmem_signal *)&sigid;

    sig->irq    = irq;
    sig->vector = xpmem_irq_to_vector(irq);

    return (xpmem_segid_fn(-1, sigid, -1, priv_data) == 0) ? IRQ_HANDLED : IRQ_NONE;
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
	ERROR("XPMEM: Cannot disconnect NULL guest\n");
	return -1;
    }

    xpmem_put_link_data(link);

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


static int
palacios_xpmem_read_apicid(xpmem_link_t link,
                           uint32_t     cpu)
{
    return apic->cpu_present_to_apicid(cpu);
}


static int
palacios_xpmem_request_irq(xpmem_link_t link,
                           uint16_t     guest_vector)
{
    struct host_xpmem_state * state       = NULL;
    int                       host_vector = 0;
    struct xpmem_idt_info     info;

    state = xpmem_get_link_data(link);
    if (state == NULL) {
	ERROR("XPMEM: Cannot request irq for link %d: invalid link\n", link);
	return -1;
    }

    /* Request irq */
    info.host_irq = xpmem_request_irq(xpmem_irq_fn, state);
    if (info.host_irq < 0) {
	ERROR("XPMEM: Cannot request irq for link %d\n", state->link);
	xpmem_put_link_data(state->link);
	return info.host_irq;
    }

    /* Get IDT vector */
    host_vector = xpmem_irq_to_vector(info.host_irq);
    if (host_vector < 0) {
	ERROR("XPMEM: Cannot convert irq %d to IDT vector\n", info.host_irq);
	xpmem_release_irq(info.host_irq, state);
	xpmem_put_link_data(state->link);
	return host_vector;
    }

    info.guest_vector = guest_vector;

    /* Update idt info */
    xpmem_set_idt_info(state, host_vector, &info);

    return host_vector;
}

static int 
palacios_xpmem_release_irq(xpmem_link_t link,
                           uint16_t     host_vector)
{
    struct host_xpmem_state * state  = NULL;
    int                       status = 0;
    struct xpmem_idt_info     info;

    state = xpmem_get_link_data(link);
    if (state == NULL) {
	ERROR("XPMEM: Cannot release irq for link %d: invalid link\n", link);
	return -EBUSY;
    }

    /* Get idt info */
    status = xpmem_get_idt_info(state, host_vector, &info);
    if (status != 0) {
	ERROR("XPMEM: Cannot get idt info for host vector %d\n", host_vector);
	return -EINVAL;
    }


    xpmem_release_irq(info.host_irq, state);

    info.host_irq     = 0;
    info.guest_vector = 0;
    info.in_use       = 0;

    /* Update idt info */
    xpmem_set_idt_info(state, host_vector, &info);

    return 0;
}

static void
palacios_xpmem_deliver_irq(xpmem_link_t  link,
                           xpmem_segid_t segid,
                           xpmem_sigid_t sigid,
                           xpmem_domid_t domid)
{
    xpmem_irq_deliver(segid, sigid, domid);
}

static struct v3_xpmem_hooks 
palacios_xpmem_hooks = 
{
    .xpmem_host_connect    = palacios_xpmem_host_connect,
    .xpmem_host_disconnect = palacios_xpmem_host_disconnect,
    .xpmem_command         = palacios_xpmem_command,
    .xpmem_read_apicid     = palacios_xpmem_read_apicid,
    .xpmem_request_irq     = palacios_xpmem_request_irq,
    .xpmem_release_irq     = palacios_xpmem_release_irq,
    .xpmem_deliver_irq     = palacios_xpmem_deliver_irq,
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

    rwlock_init(&(state->idt_lock));
    memset(state->idt_map, 0, sizeof(state->idt_map));

    state->link = xpmem_add_connection(
	    (void *)state,
	    xpmem_cmd_fn,
	    xpmem_segid_fn,
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
