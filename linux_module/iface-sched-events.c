/* Palacios Sched Events Interface
 * (c) 2013, Jack Lange <jacklange@cs.pitt.edu>
 */

#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/preempt.h>

#include "palacios.h"
#include "mm.h"
#include "linux-exts.h"

#include <interfaces/sched_events.h>

static struct list_head notifier_list;
spinlock_t notifier_lock;

struct v3_sched_notifier {
    int (*sched_in)(void * arg, int cpu);
    int (*sched_out)(void * arg, int cpu);
    void * arg;
    
    struct preempt_notifier preempt_notifier;

    struct list_head node;
};


static void 
v3_sched_in(struct preempt_notifier * pn, 
	    int                       cpu) 
{
    struct v3_sched_notifier * notifier = container_of(pn, struct v3_sched_notifier, preempt_notifier);

    if (notifier->sched_in) {
	notifier->sched_in(notifier->arg, cpu);
    }

    //    preempt_disable();
}

static void 
v3_sched_out(struct preempt_notifier * pn, 
	     struct task_struct      * next) 
{
    struct v3_sched_notifier * notifier = container_of(pn, struct v3_sched_notifier, preempt_notifier);

    if (notifier->sched_out) {
	notifier->sched_out(notifier->arg, get_cpu());
	put_cpu();
    }

    //    preempt_enable();
}


static struct preempt_ops v3_preempt_ops = {
    .sched_in  = v3_sched_in,
    .sched_out = v3_sched_out
};


static struct v3_sched_notifier * 
find_notifier(int (*sched_in)(void * arg, int cpu),
	      int (*sched_out)(void * arg, int cpu),
	      void * arg) 
{
    struct v3_sched_notifier * tmp = NULL;
    int           found = 0;
    unsigned long flags = 0;
   
    spin_lock_irqsave(&notifier_lock, flags);
    {
	list_for_each_entry(tmp, &notifier_list, node) {
	    if ((tmp->sched_in  == sched_in)   && 
		(tmp->sched_out == sched_out)  &&
		(tmp->arg       == arg)) {
		found = 1;
		break;
	    }
	}
    }
    spin_unlock_irqrestore(&notifier_lock, flags);

    if (found) {
	return tmp;
    } else {
	return NULL;
    }
}


static int palacios_hook_sched_evts(int (*sched_in)(void * arg, int cpu),
				    int (*sched_out)(void * arg, int cpu),
				    void * arg) 
{
    struct v3_sched_notifier * notifier = NULL;
    unsigned long flags;

    if (find_notifier(sched_in, sched_out, arg) != NULL) {
	ERROR("Scheduler event hook already registered\n");
	return -1;
    }

    notifier = palacios_kmalloc(sizeof(struct v3_sched_notifier), GFP_KERNEL);

    if (IS_ERR(notifier)) {
	ERROR("Error allocating v3_sched_notifier\n");
	return -1;
    }
    
    memset(notifier, 0, sizeof(struct v3_sched_notifier));

    notifier->sched_in  = sched_in;
    notifier->sched_out = sched_out;
    notifier->arg       = arg;

    preempt_notifier_init(&(notifier->preempt_notifier), &v3_preempt_ops);
    preempt_notifier_register(&(notifier->preempt_notifier));

    spin_lock_irqsave(&notifier_lock, flags);
    {
	list_add_tail(&(notifier->node), &notifier_list);
    }
    spin_unlock_irqrestore(&notifier_lock, flags);

    
    return 0;
}

static int
palacios_unhook_sched_evts(int (*sched_in)(void * arg, int cpu), 
			   int (*sched_out)(void * arg, int cpu), 
			   void * arg)
{
    struct v3_sched_notifier * notifier = NULL;
    unsigned long flags;

    notifier = find_notifier(sched_in, sched_out, arg);

    if (notifier != NULL) {
	ERROR("Could not find scheduler event state\n");
	return -1;
    }

    preempt_notifier_unregister(&(notifier->preempt_notifier));

    spin_lock_irqsave(&notifier_lock, flags);
    {
	list_del(&(notifier->node));
    }
    spin_unlock_irqrestore(&notifier_lock, flags);

    palacios_kfree(notifier);

    return -1;
}


static struct v3_sched_hooks sched_hooks = {
    .hook_sched_evts   = palacios_hook_sched_evts,
    .unhook_sched_evts = palacios_unhook_sched_evts
};


static int 
sched_events_init( void ) 
{
    INIT_LIST_HEAD(&notifier_list);
    spin_lock_init(&notifier_lock);

    V3_Init_SchedEvents(&sched_hooks);

    return 0;
}

static int 
sched_events_deinit( void ) 
{
    struct v3_sched_notifier * tmp      = NULL;
    struct v3_sched_notifier * notifier = NULL;

    list_for_each_entry_safe(notifier, tmp, &notifier_list, node) {
	preempt_notifier_unregister(&(notifier->preempt_notifier));
	list_del(&(notifier->node));
	palacios_kfree(notifier);
    }
    

    return 0;
}


static struct linux_ext sched_events_ext = {
    .name         = "SCHED_EVENTS_INTERFACE",
    .init         = sched_events_init,
    .deinit       = sched_events_deinit,
    .guest_init   = NULL,
    .guest_deinit = NULL
};


register_extension(&sched_events_ext);
