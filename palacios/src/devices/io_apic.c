/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <devices/apic.h>
#include <palacios/vm.h>
#include <palacios/vmm_lock.h>

#ifndef V3_CONFIG_DEBUG_IO_APIC
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif



#define FREE_LIST_SIZE 128

#define IO_APIC_BASE_ADDR 0xfec00000


#define IOAPIC_ID_REG          0x00
#define IOAPIC_VER_REG         0x01
#define IOAPIC_ARB_REG         0x02

#define IOAPIC_REDIR_BASE_REG  0x10

#define REDIR_LO_MASK         ~0x00005000
#define IOAPIC_REDIR_MASK_BIT  0x00010000

struct ioapic_reg_sel {
    union {
	uint32_t val;
	struct {
	    uint_t reg_addr     : 8;
	    uint_t rsvd         : 24;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

struct ioapic_id_reg {
    union {
	uint32_t val;
	struct {
	    uint_t rsvd1      : 24;
	    uint_t id         : 4;
	    uint_t rsvd2      : 4;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

struct ioapic_ver_reg {
    union {
	uint32_t val;
	struct {
	    uint_t version    : 8;
	    uint_t rsvd1      : 8;
	    uint_t max_redir  : 8;
	    uint_t rsvd2      : 8;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct ioapic_arb_reg {
    union {
	uint32_t val;
	struct {
	    uint_t rsvd1      : 24;
	    uint_t max_redir  : 4;
	    uint_t rsvd2      : 4;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct redir_tbl_entry {
    union {
	uint64_t val;
	struct {
	    uint32_t lo;
	    uint32_t hi;
	} __attribute__((packed));
	struct {
	    uint_t vec        : 8;

#define FIXED        0x0
#define LOWEST_PRIOR 0x1
#define SMI          0x2
#define NMI          0x4
#define INIT         0x5
#define EXTINT       0x7
	    uint_t del_mode   : 3;

#define PHSYICAL_DST_MODE 0
#define LOGICAL_DST_MODE 1
	    uint_t dst_mode   : 1;
	    uint_t del_status : 1;

#define HIGH_ACTIVE 0
#define LOW_ACTIVE 1
	    uint_t intr_pol   : 1;
	    uint_t rem_irr    : 1;
	    uint_t trig_mode  : 1;
	    uint_t mask       : 1;
	    uint64_t rsvd     : 39;
	    uint_t dst_field  : 8;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct ack_entry {
    uint32_t irq;
    int (*ack)(struct v3_core_info * core, uint32_t irq, void * private_data);
    void * private_data;    

    struct list_head node;
};


struct io_apic_state {
    addr_t   base_addr;

    uint32_t index_reg;


    struct ioapic_id_reg   ioapic_id;
    struct ioapic_ver_reg  ioapic_ver;
    struct ioapic_arb_reg  ioapic_arb_id;
  
    struct redir_tbl_entry redir_tbl[24];

    /* Active number of level triggered INTR lines
     * incremented on raise_irq, decremented on lower_irq
     */
    uint8_t level_cnt[24]; 

    struct list_head ack_tbl[24];
    struct list_head ack_free_list;
    
    void * apic_dev_data;

    void * router_handle;

    v3_spinlock_t ack_tbl_lock;
    v3_spinlock_t lvl_cnt_lock;

    struct v3_vm_info * vm;
};


static int ioapic_eoi(struct v3_core_info * core, uint32_t irq, void * private_data);

static void 
init_ioapic_state(struct io_apic_state * ioapic, 
		  uint32_t               id) 
{
    int i = 0;

    ioapic->base_addr = IO_APIC_BASE_ADDR;
    ioapic->index_reg = 0;

    ioapic->ioapic_id.id      = id;
    ioapic->ioapic_ver.val    = 0x00170011;
    ioapic->ioapic_arb_id.val = 0x00000000;

    for (i = 0; i < 24; i++) {
	ioapic->redir_tbl[i].val  = 0x0001000000000000LL;
	// Mask all interrupts until they are enabled....
	ioapic->redir_tbl[i].mask = 1;
	ioapic->level_cnt[i]      = 0;
	INIT_LIST_HEAD(&(ioapic->ack_tbl[i]));
    }

    INIT_LIST_HEAD(&(ioapic->ack_free_list));
    v3_spinlock_init(&(ioapic->ack_tbl_lock));
    v3_spinlock_init(&(ioapic->lvl_cnt_lock));

    for (i = 0; i < FREE_LIST_SIZE; i++) {
	struct ack_entry * tmp_entry = V3_Malloc(sizeof(struct ack_entry));

	memset(tmp_entry, 0, sizeof(struct ack_entry));
	list_add(&(tmp_entry->node), &(ioapic->ack_free_list));
    }
    
    // special case redir_tbl[0] for pin 0 as ExtInt for Virtual Wire Mode
    // ioapic->redir_tbl[0].del_mode=EXTINT;
    // ioapic->redir_tbl[0].mask=0;
}


static int 
ioapic_read(struct v3_core_info * core, 
	    addr_t                guest_addr, 
	    void                * dst, 
	    uint_t                length, 
	    void                * priv_data) 
{
    struct io_apic_state * ioapic  = (struct io_apic_state *)(priv_data);
    uint32_t               reg_tgt = guest_addr - ioapic->base_addr;
    uint32_t             * op_val  = (uint32_t *)dst;

    //    PrintDebug("ioapic %u: IOAPIC Read at %p\n", ioapic->ioapic_id.id, (void *)guest_addr);

    if (reg_tgt == 0x00) {
	*op_val = ioapic->index_reg;
    } else if (reg_tgt == 0x10) {
	// IOWIN register
	switch (ioapic->index_reg) {
	    case IOAPIC_ID_REG:
		*op_val = ioapic->ioapic_id.val;
		break;
	    case IOAPIC_VER_REG:
		*op_val = ioapic->ioapic_ver.val;
		break;
	    case IOAPIC_ARB_REG:
		*op_val = ioapic->ioapic_arb_id.val;
		break;
	    default: {
		uint_t redir_index = (ioapic->index_reg - IOAPIC_REDIR_BASE_REG) >> 1;
		uint_t hi_val      = (ioapic->index_reg - IOAPIC_REDIR_BASE_REG) &  1;
		
		PrintDebug("ioapic %u: Reading Redir TBL Entry %d (hi bits: %d)\n", 
			   ioapic->ioapic_id.id,redir_index, hi_val);
		
		if (redir_index > 0x3f) {
		    PrintError("ioapic %u: Invalid redirection table entry 0x%x\n", 
			       ioapic->ioapic_id.id, (uint32_t)redir_index);
		    return -1;
		}
		
		if (hi_val) {
		    *op_val = ioapic->redir_tbl[redir_index].hi;
		} else {
		    *op_val = ioapic->redir_tbl[redir_index].lo;
		}
		PrintDebug("ioapic %u: \t Read Value = 0x%x\n", 
			   ioapic->ioapic_id.id, *op_val);

	    }
	}
    }

    PrintDebug("ioapic %u: Read from reg_tgt=%x, ioapic->index_reg=%x, op_val=%x\n", 
	       ioapic->ioapic_id.id, reg_tgt, ioapic->index_reg, *op_val);


    return length;
}

static int 
ioapic_send_ipi(struct v3_vm_info      * vm,
		struct io_apic_state   * ioapic, 
		struct redir_tbl_entry * irq_entry) 
{
    struct v3_gen_ipi ipi;

    if (irq_entry->mask == 1) {
	PrintDebug("ioapic %u: Trying to raise masked irq (%d)\n",
		   ioapic->ioapic_id.id, irq_entry->vec);
	return 0;
    }

    PrintDebug("ioapic %u: IOAPIC Signaling APIC to raise INTR %d\n", 
	       ioapic->ioapic_id.id, irq_entry->vec);


    ipi.vector        = irq_entry->vec;
    ipi.mode          = irq_entry->del_mode;
    ipi.logical       = irq_entry->dst_mode;
    ipi.trigger_mode  = irq_entry->trig_mode;
    ipi.dst           = irq_entry->dst_field;
    ipi.dst_shorthand = 0;


    ipi.ack           = ioapic_eoi;
    ipi.private_data  = ioapic;

    if (irq_entry->trig_mode) {
	irq_entry->rem_irr = 1;
    }

    //    PrintDebug("ioapic %u: IPI: vector 0x%x, mode 0x%x, logical 0x%x, trigger 0x%x, dst 0x%x, shorthand 0x%x\n",
    //	       ioapic->ioapic_id.id, ipi.vector, ipi.mode, ipi.logical, ipi.trigger_mode, ipi.dst, ipi.dst_shorthand);
    // Need to add destination argument here...
    if (v3_apic_send_ipi(vm, &ipi, ioapic->apic_dev_data) == -1) {
	PrintError("Error sending IPI to apic %d\n", ipi.dst);
	return -1;
    }

    return 0;
}


static int 
ioapic_write(struct v3_core_info * core, 
	     addr_t                guest_addr, 
	     void                * src, 
	     uint_t                length, 
	     void                * priv_data) 
{
    struct io_apic_state * ioapic  = (struct io_apic_state *)(priv_data);
    uint32_t               reg_tgt = guest_addr - ioapic->base_addr;
    uint32_t               op_val  = *(uint32_t *)src;

    //  PrintDebug("ioapic %u: IOAPIC Write at %p (val = %d)\n",  ioapic->ioapic_id.id, (void *)guest_addr, *(uint32_t *)src);

    if (reg_tgt == 0x00) {
	//	PrintDebug("ioapic %u: Setting ioapic index register to 0x%x.\n", ioapic->ioapic_id.id, op_val);
	ioapic->index_reg = op_val;
    } else if (reg_tgt == 0x10) {
	// IOWIN register
	switch (ioapic->index_reg) {
	    case IOAPIC_ID_REG:
		// What does this do to our relationship with the ICC bus?
		ioapic->ioapic_id.val = op_val;
		break;
	    case IOAPIC_VER_REG:
		// GPF/PageFault/Ignore?
		PrintError("ioapic %u: Writing to read only IOAPIC register\n", ioapic->ioapic_id.id);
		return -1;
	    case IOAPIC_ARB_REG:
		ioapic->ioapic_arb_id.val = op_val;
		break;
	    default: {
		    uint_t redir_index = (ioapic->index_reg - IOAPIC_REDIR_BASE_REG) >> 1;
		    uint_t hi_val      = (ioapic->index_reg - IOAPIC_REDIR_BASE_REG) &  1;

		    struct redir_tbl_entry * irq_entry   = &(ioapic->redir_tbl[redir_index]);

		    /*	    PrintDebug("ioapic %u: Writing value 0x%x to redirection entry %u (%s)\n",
		           ioapic->ioapic_id.id, op_val, redir_index, hi_val ? "hi" : "low");
		    */

		    if (redir_index > 0x3f) {
			PrintError("ioapic %u: Invalid redirection table entry %x\n", 
				   ioapic->ioapic_id.id, (uint32_t)redir_index);
			return -1;
		    }
		    if (hi_val) {
			PrintDebug("ioapic %u: Writing to hi of pin %d (val=0x%x)\n", 
				   ioapic->ioapic_id.id, redir_index, op_val);

			ioapic->redir_tbl[redir_index].hi = op_val;
		    } else {
			PrintDebug("ioapic %u: Writing to lo of pin %d (val=0x%x)\n", 
				   ioapic->ioapic_id.id, redir_index, op_val);

			op_val        &=  REDIR_LO_MASK;
			irq_entry->lo &= ~REDIR_LO_MASK;
			irq_entry->lo |=  op_val;

			// send pending irqs after unmask

                        if ( (irq_entry->mask                == 0) && 
			     (irq_entry->trig_mode           == 1) && 
			     (ioapic->level_cnt[redir_index] >  0) ) {

			    PrintDebug("  Resend pending IRQ\n");
			    
			    if (ioapic_send_ipi(core->vm_info, ioapic, irq_entry) == -1) {
				PrintError("Error: %s: ioapic %u,APIC vector=%d\n", 
					   __func__, ioapic->ioapic_id.id, irq_entry->vec);
			    }
			}
		    }
                    
		}
	}
    }

    return length;
}




static int 
ioapic_eoi(struct v3_core_info * core, 
	   uint32_t              irq, 
	   void                * private_data) 
{
    struct io_apic_state   * ioapic    = (struct io_apic_state *)(private_data);  
    struct redir_tbl_entry * irq_entry = NULL;
    unsigned int             flags     = 0;
    int i = 0;

    
    for (i = 0; i < 24; i++) {
	struct ack_entry * ack = NULL;
	struct ack_entry * tmp = NULL;

	irq_entry = &(ioapic->redir_tbl[i]);

	if (irq_entry->vec != irq) {
	    continue;
	}

	flags = v3_spin_lock_irqsave(ioapic->ack_tbl_lock);

	list_for_each_entry_safe(ack, tmp, &(ioapic->ack_tbl[i]), node) {
	    PrintDebug("ioapic %u: ACKING IOAPIC IRQ (fn=%p) apic_irq=%d, ioapic_irq=%d\n", 
		       ioapic->ioapic_id.id, ack->ack, irq, ack->irq);

	    ack->ack(core, ack->irq, ack->private_data);

	    ack->ack          = NULL;
	    ack->private_data = NULL;
	    ack->irq          = 0;

	    list_move_tail(&(ack->node), &(ioapic->ack_free_list));
	}
	v3_spin_unlock_irqrestore(ioapic->ack_tbl_lock, flags);


	if (irq_entry->trig_mode) {
	    irq_entry->rem_irr = 0;
	    
	    if (ioapic->level_cnt[i] > 0) {
		if (ioapic_send_ipi(core->vm_info, ioapic, irq_entry) == -1) {
		    PrintError("Error: ioapic %u - resending IPI after EOI (IRQ=%d) (APIC vector=%d)\n", 
			       ioapic->ioapic_id.id, irq, irq_entry->vec);
		}
	    }
	}
    }


    return 0;
}




static int 
ioapic_raise_irq(struct v3_vm_info * vm, 
		 void              * private_data, 
		 struct v3_irq     * irq) 
{
    struct io_apic_state   * ioapic    = (struct io_apic_state *)(private_data);  
    struct redir_tbl_entry * irq_entry = NULL;
    uint8_t                  irq_num   = irq->irq;
  
    if (irq_num == 0) { 
      // IRQ 0 being raised, in the Palacios context, means the PIT
      // However, the convention is that it is the PIC that is connected
      // to PIN 0 of the IOAPIC and the PIT is connected to pin 2
      // Hence we convert this to the relvant pin.  In the future,
      // the PIC may signal to the IOAPIC in a different path.
      // Yes, this is kind of hideous, but it is needed to have the
      // PIT correctly show up via the IOAPIC
      irq_num = 2;
    }

    if (irq_num > 24) {
	PrintDebug("ioapic %u: IRQ out of range of IO APIC\n", ioapic->ioapic_id.id);
	return -1;
    }

    irq_entry = &(ioapic->redir_tbl[irq_num]);


    if (irq_entry->trig_mode) {
	unsigned int flags = 0;

	/* We might be sharing a vector here, so we coallesce in the IO-APIC
	 * The IO-APIC is then responsible for acking each device
	 * Each device is responsible for lowering the IRQ line to decrement the level count
	 */	

	PrintDebug("ioapic %u: Incrementing level_cnt for ioapic.irq=%d (prev_val=%d)\n", 
		   ioapic->ioapic_id.id, irq_num, ioapic->level_cnt[irq_num]);

	flags = v3_spin_lock_irqsave(ioapic->lvl_cnt_lock);
	{
	    ioapic->level_cnt[irq_num]++;
	}
	v3_spin_unlock_irqrestore(ioapic->lvl_cnt_lock, flags);
    }


    if (irq->ack) {
	struct ack_entry * tmp_ack_entry = NULL;
	unsigned int flags = 0;

	flags = v3_spin_lock_irqsave(ioapic->ack_tbl_lock);	
	{
	    // scan for identical call sites, if one exists then this interrupt is ignored. 
	    list_for_each_entry(tmp_ack_entry, &(ioapic->ack_tbl[irq_num]), node) {

		if ((tmp_ack_entry->ack          == irq->ack) && 
		    (tmp_ack_entry->private_data == irq->private_data)) {
		    
		    // Refire of a level triggered IRQ, safe to ignore
		    v3_spin_unlock_irqrestore(ioapic->ack_tbl_lock, flags);
		    return 0;
		}
	    }
	    
	    if (list_empty(&(ioapic->ack_free_list))) {
		PrintError("Error: ioapic %u - Callback free list is exhausted...\n", ioapic->ioapic_id.id);
		v3_spin_unlock_irqrestore(ioapic->ack_tbl_lock, flags);
		return -1;
	    }
	    
	    // Add callback to ack_tbl
	    tmp_ack_entry = list_first_entry(&(ioapic->ack_free_list), struct ack_entry, node);
	    
	    tmp_ack_entry->irq          = irq->irq;
	    tmp_ack_entry->ack          = irq->ack;
	    tmp_ack_entry->private_data = irq->private_data;
	    
	    list_move_tail(&(tmp_ack_entry->node), &(ioapic->ack_tbl[irq_num]));
	}
	v3_spin_unlock_irqrestore(ioapic->ack_tbl_lock, flags);
    }




    if (ioapic_send_ipi(vm, ioapic, irq_entry) == -1) {
	PrintError("Error: ioapic %u - sending IPI (vector=%d) in IOAPIC raise IRQ\n",
		   ioapic->ioapic_id.id, irq_entry->vec);
	return -1;
    }

    return 0;
}

static int 
ioapic_lower_irq(struct v3_vm_info * vm, 
		 void              * private_data, 
		 struct v3_irq     * irq) 
{
    struct io_apic_state   * ioapic    = (struct io_apic_state *)(private_data);  
    struct redir_tbl_entry * irq_entry = NULL;
    uint8_t      irq_num = irq->irq;
    unsigned int flags   = 0;

    if (irq_num == 0) { 
      // IRQ 0 being raised, in the Palacios context, means the PIT
      // However, the convention is that it is the PIC that is connected
      // to PIN 0 of the IOAPIC and the PIT is connected to pin 2
      // Hence we convert this to the relvant pin.  In the future,
      // the PIC may signal to the IOAPIC in a different path.
      // Yes, this is kind of hideous, but it is needed to have the
      // PIT correctly show up via the IOAPIC
      irq_num = 2;
    }

    if (irq_num > 24) {
	PrintDebug("ioapic %u: IRQ out of range of IO APIC\n", ioapic->ioapic_id.id);
	return -1;
    }

    irq_entry = &(ioapic->redir_tbl[irq_num]);

    if (irq_entry->trig_mode) {
	
	flags = v3_spin_lock_irqsave(ioapic->lvl_cnt_lock);
	{	
	    if (ioapic->level_cnt[irq_num] <= 0) {
		PrintError("Error: ioapic %u - No active IRQ line to lower (irq_num=%d) (lvl_cnt=%d)\n", 
			   ioapic->ioapic_id.id,
			   irq_num, 
			   ioapic->level_cnt[irq_num] );

		v3_spin_unlock_irqrestore(ioapic->lvl_cnt_lock, flags);		
		return -1;
	    }
	    
	    PrintDebug("ioapic %u: Decrementing lvl cnt for ioapic.irq=%d (prev_val=%d)\n", 
		       ioapic->ioapic_id.id, irq_num, ioapic->level_cnt[irq_num]);
	    
	    ioapic->level_cnt[irq_num]--;
	}
	v3_spin_unlock_irqrestore(ioapic->lvl_cnt_lock, flags);

    }

    return 0;
}

static struct intr_router_ops router_ops = {
    .raise_intr = ioapic_raise_irq,
    .lower_intr = ioapic_lower_irq, 
};




static int
io_apic_free(struct io_apic_state * ioapic) 
{
    //    struct redir_tbl_entry * irq_entry = NULL;
    struct ack_entry * ack = NULL;
    struct ack_entry * tmp = NULL;    
    int i = 0;

    v3_remove_intr_router(ioapic->vm, ioapic->router_handle);

    //TODO:  unhook memory

    //loop through ack table
    for (i = 0; i < 24; i++) {
	list_for_each_entry_safe(ack, tmp, &(ioapic->ack_tbl[i]), node) {
	    list_del(&(ack->node));
	    V3_Free(ack);
	}
    }
    
    //loop through ack_free_list
    list_for_each_entry_safe(ack, tmp, &(ioapic->ack_free_list), node) {
	list_del(&(ack->node));
	V3_Free(ack);
    }
    

    V3_Free(ioapic);

    return 0;
}

#ifdef V3_CONFIG_CHECKPOINT
static int
io_apic_save(struct v3_chkpt_ctx * ctx, 
	     void                * private_data) 
{
    struct io_apic_state * io_apic = (struct io_apic_state *)private_data;

    V3_CHKPT_STD_SAVE(ctx, io_apic->base_addr);
    V3_CHKPT_STD_SAVE(ctx, io_apic->index_reg);
    V3_CHKPT_STD_SAVE(ctx, io_apic->ioapic_id);
    V3_CHKPT_STD_SAVE(ctx, io_apic->ioapic_ver);
    V3_CHKPT_STD_SAVE(ctx, io_apic->ioapic_arb_id);
    V3_CHKPT_STD_SAVE(ctx, io_apic->redir_tbl);

    return 0;
}

static int 
io_apic_load(struct v3_chkpt_ctx * ctx, 
	     void                * private_data) 
{
    struct io_apic_state * io_apic = (struct io_apic_state *)private_data;

    V3_CHKPT_STD_LOAD(ctx, io_apic->base_addr);
    V3_CHKPT_STD_LOAD(ctx, io_apic->index_reg);
    V3_CHKPT_STD_LOAD(ctx, io_apic->ioapic_id);
    V3_CHKPT_STD_LOAD(ctx, io_apic->ioapic_ver);
    V3_CHKPT_STD_LOAD(ctx, io_apic->ioapic_arb_id);
    V3_CHKPT_STD_LOAD(ctx, io_apic->redir_tbl);

    return 0;
}
#endif



static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))io_apic_free,
#ifdef V3_CONFIG_CHECKPOINT
    .save = io_apic_save, 
    .load = io_apic_load
#endif
};



static int 
ioapic_init(struct v3_vm_info * vm, 
	    v3_cfg_tree_t     * cfg) 
{
    struct vm_device * apic_dev = v3_find_dev(vm, v3_cfg_val(cfg, "apic"));
    char             * dev_id   = v3_cfg_val(cfg, "ID");


    PrintDebug("ioapic: Creating IO APIC\n");

    struct io_apic_state * ioapic = (struct io_apic_state *)V3_Malloc(sizeof(struct io_apic_state));

    if (!ioapic) {
	PrintError("Cannot allocate in init\n");
	return -1;
    }

    ioapic->apic_dev_data = apic_dev;

    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, ioapic);

    if (dev == NULL) {
	PrintError("ioapic: Could not attach device %s\n", dev_id);
	V3_Free(ioapic);
	return -1;
    }

    ioapic->router_handle = v3_register_intr_router(vm, &router_ops, ioapic);
    ioapic->vm            = vm;

    init_ioapic_state(ioapic, vm->num_cores);

    v3_hook_full_mem(vm, V3_MEM_CORE_ANY, 
		     ioapic->base_addr, 
		     ioapic->base_addr + PAGE_SIZE_4KB, 
		     ioapic_read, ioapic_write, ioapic);
  
    return 0;
}


device_register("IOAPIC", ioapic_init)
