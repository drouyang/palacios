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
#include <palacios/vmm_lock.h>
#include <devices/lnx_virtio_pci.h>
#include <palacios/vm_guest_mem.h>

#include <devices/pci.h>


#ifndef V3_CONFIG_DEBUG_VIRTIO_BLOCK
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif


#define SECTOR_SIZE 512

#define BLK_CAPACITY_PORT     20
#define BLK_MAX_SIZE_PORT     28
#define BLK_MAX_SEG_PORT      32
#define BLK_CYLINDERS_PORT    36
#define BLK_HEADS_PORT        38
#define BLK_SECTS_PORT        39

#define BLK_IN_REQ            0
#define BLK_OUT_REQ           1
#define BLK_SCSI_CMD          2

#define BLK_BARRIER_FLAG      0x80000000

#define BLK_STATUS_OK             0
#define BLK_STATUS_ERR            1
#define BLK_STATUS_NOT_SUPPORTED  2


struct blk_config {
    uint64_t capacity;
    uint32_t max_size;
    uint32_t max_seg;
    uint16_t cylinders;
    uint8_t  heads;
    uint8_t  sectors;
    /*
    uint32_t blk_size;
    uint8_t  phys_block_exp;
    uint8_t  alignment_offset;
    uint16_t min_io_size;
    uint32_t opt_io_size;
    */
} __attribute__((packed));



struct blk_op_hdr {
    uint32_t type;
    uint32_t prior;
    uint64_t sector;
} __attribute__((packed));

#define QUEUE_SIZE 128

/* Host Feature flags */
#define VIRTIO_BARRIER       0x01       /* Does host support barriers? */
#define VIRTIO_SIZE_MAX      0x02       /* Indicates maximum segment size */
#define VIRTIO_SEG_MAX       0x04       /* Indicates maximum # of segments */
#define VIRTIO_LEGACY_GEOM   0x10       /* Indicates support of legacy geometry */


struct virtio_dev_state {
    struct vm_device * pci_bus;
    struct list_head   dev_list;
};


struct virtio_blk_state {
    struct pci_device     * pci_dev;
    struct blk_config       block_cfg;
    struct virtio_config    virtio_cfg;

    struct virtio_queue     queue;

    struct v3_dev_blk_ops * ops;

    void * backend_data;

    int    io_range_size;

    struct virtio_dev_state * virtio_dev;

    struct list_head dev_link;

    struct shadow_vring_desc shadow_desc[QUEUE_SIZE]; 
    uint16_t shadow_avail_idx;
    uint16_t shadow_used_idx;

    v3_spinlock_t isr_lock;

    /* async IO request queue */
    int    async_enabled;
    int    async_thread_should_stop;
    void * async_thread;

};



static int 
blk_reset(struct virtio_blk_state * virtio) 
{

    virtio->queue.ring_desc_addr  = 0;
    virtio->queue.ring_avail_addr = 0;
    virtio->queue.ring_used_addr  = 0;
    virtio->queue.pfn             = 0;
    virtio->queue.cur_avail_idx   = 0;

    virtio->virtio_cfg.status     = 0;
    virtio->virtio_cfg.pci_isr    = 0;

    virtio->shadow_used_idx       = 0;
    virtio->shadow_avail_idx      = 0;
    return 0;
}

static void 
vq_notify(struct virtio_blk_state * blk_state) 
{
    struct virtio_queue * vq = &(blk_state->queue);

    if (!(vq->avail->flags & VIRTIO_NO_IRQ_FLAG)) {

        v3_spin_lock(blk_state->isr_lock);
	{
	    if (blk_state->virtio_cfg.pci_isr == 0) {

		PrintDebug("virtio_blk isr value: 0 -> 1, raise IRQ %d...\n", 
			   blk_state->pci_dev->config_header.intr_line);

		blk_state->virtio_cfg.pci_isr = 1;

		v3_pci_raise_irq(blk_state->virtio_dev->pci_bus, blk_state->pci_dev, 0);
	    } else {
		PrintDebug("virtio_blk isr value: 1 -> 1\n");
	    }
	}
	v3_spin_unlock(blk_state->isr_lock);
    } else {
        PrintDebug("%s: VIRTIO_NO_IRQ_FLAG is set\n", __func__);
    }
}

static inline void 
vq_complete(struct virtio_blk_state * blk_state, 
	    uint64_t                  index, 
	    uint64_t                  req_len)
{
    struct virtio_queue * vq = &(blk_state->queue);

    PrintDebug("complete avail_index %llu into used_index %d\n", 
	       index           % QUEUE_SIZE, 
	       vq->used->index % QUEUE_SIZE);

    vq->used->ring[vq->used->index % QUEUE_SIZE].id     = vq->avail->ring[index % QUEUE_SIZE];
    vq->used->ring[vq->used->index % QUEUE_SIZE].length = req_len;
    vq->used->index++;

    vq_notify(blk_state);
}


static int 
get_desc_count(struct virtio_queue * q, 
	       int                   index) 
{
    struct vring_desc * tmp_desc = &(q->desc[index]);
    int cnt = 1;
    
    while (tmp_desc->flags & VIRTIO_NEXT_FLAG) {
	tmp_desc = &(q->desc[tmp_desc->next]);
	cnt++;
    }

    return cnt;
}


static int 
fill_shadow_desc_buf(struct v3_core_info     * core, 
		     struct virtio_blk_state * blk_state, 
		     int                       avail_idx) 
{
    struct virtio_queue      * q           = &(blk_state->queue);
    struct shadow_vring_desc * shadow_desc = blk_state->shadow_desc;

    while (q->cur_avail_idx != avail_idx) {
        struct vring_desc * hdr_desc    = NULL;
        struct vring_desc * buf_desc    = NULL;
        struct vring_desc * status_desc = NULL;
      
	uint16_t desc_idx = q->avail->ring[q->cur_avail_idx % QUEUE_SIZE];
        int      desc_cnt = get_desc_count(q, desc_idx);
        int i;

        PrintDebug("%s: cur_avail_idx %d, avail_idx %d\n", 
                __func__, q->cur_avail_idx, avail_idx);

        if (desc_cnt < 3) {
            PrintError("Block operations must include at least 3 descriptors\n");
            return -1;
        }

        /* header desc */
        hdr_desc = &(q->desc[desc_idx]);
        memcpy(&shadow_desc[desc_idx], hdr_desc, sizeof(struct vring_desc));

        if (v3_gpa_to_hva(core, hdr_desc->addr_gpa, 
			  (void *) &(shadow_desc[desc_idx].addr_hva)) == -1) {
	    
            PrintError("Could not translate block header address\n");
            return -1;
        }

        desc_idx = hdr_desc->next;

        /* buf desc */
        for (i = 0; i < desc_cnt - 2; i++) {
            buf_desc = &(q->desc[desc_idx]);
            memcpy(&shadow_desc[desc_idx], buf_desc, sizeof(struct vring_desc));

            if (v3_gpa_to_hva(core, buf_desc->addr_gpa, 
			      (void *) &shadow_desc[desc_idx].addr_hva) == -1) {
                PrintError("Could not translate buffer address %d\n", i);
                return -1;
            }

            desc_idx = buf_desc->next;
        }

        /* status desc */
        status_desc = &(q->desc[desc_idx]);
        memcpy(&shadow_desc[desc_idx], status_desc, sizeof(struct vring_desc));

        if (v3_gpa_to_hva(core, status_desc->addr_gpa, 
			  (void *)&(shadow_desc[desc_idx].addr_hva)) == -1) {
            PrintError("Could not translate status address\n");
            return -1;
        }

        q->cur_avail_idx            += 1;
        blk_state->shadow_avail_idx += 1;
    }

    return 0;
}


static int 
_handle_kick(struct virtio_blk_state * blk_state)
{
    struct virtio_queue * q = &(blk_state->queue);
    uint16_t idx     = 0;
    uint16_t end_idx = 0;

    idx     = blk_state->shadow_used_idx;
    end_idx = blk_state->shadow_avail_idx;


    while (idx != blk_state->shadow_avail_idx) {
        struct shadow_vring_desc * hdr_desc    = NULL;
        struct shadow_vring_desc * buf_desc    = NULL;
        struct shadow_vring_desc * status_desc = NULL;

        uint16_t   desc_idx = q->avail->ring[idx % QUEUE_SIZE];
        int        desc_cnt = get_desc_count(q, desc_idx);
        uint64_t   req_len  = 0;
        uint8_t    status   = BLK_STATUS_OK;
	v3_iov_t * iov_arr  = NULL;

        struct blk_op_hdr hdr;
	int ret = 0;
        int i   = 0; 

        PrintDebug("%s: shadow_used_idx=%d (mod=%d), shadow_avail_index=%d (mod=%d)\n", 
		   __func__,
		   blk_state->shadow_used_idx,  blk_state->shadow_used_idx  % QUEUE_SIZE, 
		   blk_state->shadow_avail_idx, blk_state->shadow_avail_idx % QUEUE_SIZE);
        //PrintDebug("Descriptor Count=%d, index=%d\n", desc_cnt, idx % QUEUE_SIZE);

        hdr_desc = &(blk_state->shadow_desc[desc_idx]);
        // We copy the block op header out because we are going to modify its contents
        memcpy(&hdr, (void *)hdr_desc->addr_hva, sizeof(struct blk_op_hdr));
        //PrintDebug("Header Descriptor (ptr=%p) hva=%p, len=%d, flags=%x, next=%d\n", hdr_desc, 
        //        (void *)(hdr_desc->addr_hva), hdr_desc->length, hdr_desc->flags, hdr_desc->next);	



        //PrintDebug("Blk Op Hdr (ptr=%p) type=%d, sector=%p\n", 
        //        (void *)hdr_desc->addr_hva, hdr.type, (void *)hdr.sector);

        desc_idx = hdr_desc->next;
	
	iov_arr = V3_Malloc(sizeof(v3_iov_t) * (desc_cnt - 2));
	memset(iov_arr, 0,  sizeof(v3_iov_t) * (desc_cnt - 2));

        for (i = 0; i < desc_cnt - 2; i++) {
            buf_desc = &(blk_state->shadow_desc[desc_idx]);

	    iov_arr[i].iov_base = (void *)buf_desc->addr_hva;
	    iov_arr[i].iov_len  = buf_desc->length;

            PrintDebug("Buffer Descriptor (ptr=%p) hva=%p, len=%d, flags=%x, next=%d\n", buf_desc, 
		       (void *)(buf_desc->addr_hva), buf_desc->length, buf_desc->flags, buf_desc->next);

            req_len    += buf_desc->length;
            desc_idx    = buf_desc->next;

	}

	if (hdr.type == BLK_IN_REQ) {
	    PrintDebug("Issue read\n");

	    ret = blk_state->ops->readv(iov_arr,
					desc_cnt - 2,
					hdr.sector * SECTOR_SIZE,
					blk_state->backend_data);

	    if (ret < 0) {
		PrintError("Read Error\n");
		status = BLK_STATUS_ERR;
	    }
	} else if (hdr.type == BLK_OUT_REQ) {
	    PrintDebug("Issue write\n");

	    ret = blk_state->ops->writev(iov_arr,
					 desc_cnt - 2,
					 hdr.sector * SECTOR_SIZE,
					 blk_state->backend_data);
		
	    if (ret < 0) {
		PrintError("Write Error\n");
		status = BLK_STATUS_ERR;
	    }
	} else {
	    PrintDebug("Unsupported\n");
	    status = BLK_STATUS_NOT_SUPPORTED;
	}

	V3_Free(iov_arr);


        status_desc                         = &(blk_state->shadow_desc[desc_idx]);
        req_len                            += status_desc->length;
        *((uint8_t *)status_desc->addr_hva) = status;

	/*
        PrintDebug("Status Descriptor (ptr=%p) hva=%p, len=%d, flags=%x, next=%d\n", status_desc, 
		   (void *)(status_desc->addr_hva), 
		   status_desc->length, 
		   status_desc->flags, 
		   status_desc->next);
	*/

        vq_complete(blk_state, idx, req_len);

        idx                        += 1;
        blk_state->shadow_used_idx += 1;
    }

    return 0;
}

static int 
io_dispatcher(void * arg) 
{
    struct virtio_blk_state * blk_state = (struct virtio_blk_state *)arg;

    PrintDebug("Start io_dispatcher\n");

    while (blk_state->async_thread_should_stop == 0) {
        if (blk_state->shadow_used_idx == blk_state->shadow_avail_idx) {
            v3_yield(NULL, -1);
            continue;
        }

        PrintDebug("%s: handle_kick\n", __func__);
        _handle_kick(blk_state);
    }

    blk_state->async_thread = NULL;

    return 0;
}



static int 
handle_kick(struct v3_core_info     * core, 
	    struct virtio_blk_state * blk_state)
{
    int avail_idx = blk_state->queue.avail->index;

    if (fill_shadow_desc_buf(core, blk_state, avail_idx) < 0) {
        PrintError("fill_shadow_desc_buf failed at index %d\n", avail_idx);
        return -1;
    }

    if (blk_state->async_enabled) {
        return 0;
    } else {
        return _handle_kick(blk_state);
    }
}

static int 
virtio_io_write(struct v3_core_info * core,
		uint16_t              port, 
		void                * src, 
		uint_t                length, 
		void                * private_data) 
{
    struct virtio_blk_state * blk_state = (struct virtio_blk_state *)private_data;
    int                       port_idx  = port % blk_state->io_range_size;


    PrintDebug("VIRTIO BLOCK Write for port %d (index=%d) len=%d, value=%x\n", 
	       port, port_idx,  length, *(uint32_t *)src);


    switch (port_idx) {
	case GUEST_FEATURES_PORT:
	    if (length != 4) {
		PrintError("Illegal write length for guest features\n");
		return -1;
	    }
	    
	    blk_state->virtio_cfg.guest_features = *(uint32_t *)src;
	    PrintDebug("Setting Guest Features to %x\n", blk_state->virtio_cfg.guest_features);

	    break;
	case VRING_PG_NUM_PORT:
	    if (length == 4) {
		addr_t pfn = *(uint32_t *)src;
		addr_t page_addr = (pfn << VIRTIO_PAGE_SHIFT);


		blk_state->queue.pfn = pfn;
		
		blk_state->queue.ring_desc_addr  = page_addr ;
		blk_state->queue.ring_avail_addr = page_addr + (QUEUE_SIZE * sizeof(struct vring_desc));
		blk_state->queue.ring_used_addr  = blk_state->queue.ring_avail_addr + sizeof(struct vring_avail) + (QUEUE_SIZE * sizeof(uint16_t));
		
		// round up to next page boundary.
		blk_state->queue.ring_used_addr = (blk_state->queue.ring_used_addr + 0xfff) & ~0xfff;

		if (v3_gpa_to_hva(core, blk_state->queue.ring_desc_addr, (addr_t *)&(blk_state->queue.desc)) == -1) {
		    PrintError("Could not translate ring descriptor address\n");
		    return -1;
		}


		if (v3_gpa_to_hva(core, blk_state->queue.ring_avail_addr, (addr_t *)&(blk_state->queue.avail)) == -1) {
		    PrintError("Could not translate ring available address\n");
		    return -1;
		}


		if (v3_gpa_to_hva(core, blk_state->queue.ring_used_addr, (addr_t *)&(blk_state->queue.used)) == -1) {
		    PrintError("Could not translate ring used address\n");
		    return -1;
		}

		PrintDebug("RingDesc_addr=%p, Avail_addr=%p, Used_addr=%p\n",
			   (void *)(blk_state->queue.ring_desc_addr),
			   (void *)(blk_state->queue.ring_avail_addr),
			   (void *)(blk_state->queue.ring_used_addr));

		PrintDebug("RingDesc=%p, Avail=%p, Used=%p\n", 
			   blk_state->queue.desc, blk_state->queue.avail, blk_state->queue.used);

	    } else {
		PrintError("Illegal write length for page frame number\n");
		return -1;
	    }
	    break;
	case VRING_Q_SEL_PORT:
	    blk_state->virtio_cfg.vring_queue_selector = *(uint16_t *)src;

	    if (blk_state->virtio_cfg.vring_queue_selector != 0) {
		PrintError("Virtio Block device only uses 1 queue, selected %d\n", 
			   blk_state->virtio_cfg.vring_queue_selector);
		return -1;
	    }

	    break;
	case VRING_Q_NOTIFY_PORT:
            if (handle_kick(core, blk_state) == -1) {
                PrintError("Could not handle Block Notification\n");
            }
	    break;
	case VIRTIO_STATUS_PORT:
	    blk_state->virtio_cfg.status = *(uint8_t *)src;

	    if (blk_state->virtio_cfg.status == 0) {
		PrintDebug("Resetting device\n");
		blk_reset(blk_state);
	    }

	    break;

	case VIRTIO_ISR_PORT:
            v3_spin_lock(blk_state->isr_lock);
	    {
		blk_state->virtio_cfg.pci_isr = *(uint8_t *)src;
	    }
            v3_spin_unlock(blk_state->isr_lock);
	    break;
	default:
	    return -1;
	    break;
    }

    return length;
}


static int 
virtio_io_read(struct v3_core_info * core, 
	       uint16_t              port, 
	       void                * dst, 
	       uint_t                length, 
	       void                * private_data) 
{
    struct virtio_blk_state * blk_state = (struct virtio_blk_state *)private_data;
    int                       port_idx  = port % blk_state->io_range_size;


    PrintDebug("VIRTIO BLOCK Read  for port %d (index =%d), length=%d\n", 
	       port, port_idx, length);


    switch (port_idx) {
	case HOST_FEATURES_PORT:
	case HOST_FEATURES_PORT + 1:
	case HOST_FEATURES_PORT + 2:
	case HOST_FEATURES_PORT + 3:
	    if (port_idx + length > HOST_FEATURES_PORT + 4) {
		PrintError("Illegal read length for host features (len=%d)\n", length);
		return -1;
	    }

	    memcpy(dst, &(blk_state->virtio_cfg.host_features), length);
	    break;
	case VRING_PG_NUM_PORT:
	case VRING_PG_NUM_PORT + 1:
	case VRING_PG_NUM_PORT + 2:
	case VRING_PG_NUM_PORT + 3:
	    if (port_idx + length > VRING_PG_NUM_PORT + 4) {
		PrintError("Illegal read length for vring pg num (len=%d)\n", length);
		return -1;
	    }

	    memcpy(dst, &(blk_state->queue.pfn), length);
	    break;
	case VRING_SIZE_PORT:
	case VRING_SIZE_PORT + 1:
	    if (length > 2) {
		PrintError("Illegal read length for vring size (len=%d)\n", length);
		return -1;
	    }
	    
	    memcpy(dst, &(blk_state->queue.queue_size), length);

	    break;

	case VIRTIO_STATUS_PORT:
	    if (length != 1) {
		PrintError("Illegal read length for status (len=%d)\n", length);
		return -1;
	    }

	    *(uint8_t *)dst = blk_state->virtio_cfg.status;
	    break;

	case VIRTIO_ISR_PORT:
            v3_spin_lock(blk_state->isr_lock);
	    {
		*(uint8_t *)dst = blk_state->virtio_cfg.pci_isr;
		
		if (blk_state->virtio_cfg.pci_isr == 1) {
		    blk_state->virtio_cfg.pci_isr = 0;
		    PrintDebug("Lowering IRQ from Virtio BLOCK...\n");

		    v3_pci_lower_irq(blk_state->virtio_dev->pci_bus, blk_state->pci_dev, 0);
		} else {
		    PrintDebug("VIRTIO_ISR_PORT: isr not set\n");
		}
	    }
            v3_spin_unlock(blk_state->isr_lock);

	    break;

	default:
	    if ( (port_idx >= sizeof(struct virtio_config)) && 
		 (port_idx < (sizeof(struct virtio_config) + sizeof(struct blk_config))) ) {
		int       cfg_offset = port_idx - sizeof(struct virtio_config);
		uint8_t * cfg_ptr    = (uint8_t *)&(blk_state->block_cfg);

		memcpy(dst, cfg_ptr + cfg_offset, length);
		
	    } else {
		PrintError("Read of Unhandled Virtio Read. Returning 0\n");

		if (length == 1) {
		    *(uint8_t  *)dst = 0;
		} else if (length == 2) {
		    *(uint16_t *)dst = 0;
		} else if (length == 4) {
		    *(uint32_t *)dst = 0;
		}
	    }
	  
	    break;
    }

    return length;
}


static int 
virtio_free(struct virtio_dev_state * virtio) 
{
    struct virtio_blk_state * blk_state = NULL;
    struct virtio_blk_state * tmp       = NULL;

    blk_state->async_thread_should_stop = 1;

    while (blk_state->async_thread != NULL) {
	v3_yield(NULL, -1);
	__asm__ __volatile__ ("":::"memory");
    }


    list_for_each_entry_safe(blk_state, tmp, &(virtio->dev_list), dev_link) {

	// unregister from PCI

	list_del(&(blk_state->dev_link));
	V3_Free(blk_state);
    }
    

    V3_Free(virtio);

    return 0;
}



static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))virtio_free,

};





static int 
register_dev(struct virtio_dev_state * virtio, 
	     struct virtio_blk_state * blk_state) 
{
    // initialize PCI
    struct pci_device * pci_dev = NULL;
    struct v3_pci_bar   bars[6];
    int num_ports = sizeof(struct virtio_config) + sizeof(struct blk_config);
    int tmp_ports = num_ports;
    int i;



    // This gets the number of ports, rounded up to a power of 2
    blk_state->io_range_size = 1; // must be a power of 2
    
    while (tmp_ports > 0) {
	tmp_ports                >>= 1;
	blk_state->io_range_size <<= 1;
    }
	
    // this is to account for any low order bits being set in num_ports
    // if there are none, then num_ports was already a power of 2 so we shift right to reset it
    if ((num_ports & ((blk_state->io_range_size >> 1) - 1)) == 0) {
	blk_state->io_range_size >>= 1;
    }
    
    
    for (i = 0; i < 6; i++) {
	bars[i].type = PCI_BAR_NONE;
    }
    
    PrintDebug("Virtio-BLK io_range_size = %d\n", blk_state->io_range_size);
    
    bars[0].type              = PCI_BAR_IO;
    bars[0].default_base_port = -1;
    bars[0].num_ports         = blk_state->io_range_size;
    
    bars[0].io_read           = virtio_io_read;
    bars[0].io_write          = virtio_io_write;
    bars[0].private_data      = blk_state;
    
    pci_dev = v3_pci_register_device(virtio->pci_bus, PCI_STD_DEVICE, 
				     0, PCI_AUTO_DEV_NUM, 0,
				     "LNX_VIRTIO_BLK", bars,
				     NULL, NULL, NULL, NULL, blk_state);
    
    if (!pci_dev) {
	PrintError("Could not register PCI Device\n");
	return -1;
    }

    blk_state->pci_dev    = pci_dev;
    blk_state->virtio_dev = virtio;
    
    pci_dev->config_header.vendor_id           = VIRTIO_VENDOR_ID;
    pci_dev->config_header.subsystem_vendor_id = VIRTIO_SUBVENDOR_ID;
    pci_dev->config_header.device_id           = VIRTIO_BLOCK_DEV_ID;
    pci_dev->config_header.class               = PCI_CLASS_STORAGE;
    pci_dev->config_header.subclass            = PCI_STORAGE_SUBCLASS_OTHER;
    pci_dev->config_header.subsystem_id        = VIRTIO_BLOCK_SUBDEVICE_ID;
    pci_dev->config_header.intr_pin            = 1;
    pci_dev->config_header.max_latency         = 1; // ?? (qemu does it...)
        

    /* Add backend to list of devices */
    list_add(&(blk_state->dev_link), &(virtio->dev_list));
    
    /* Block configuration */
    blk_state->virtio_cfg.host_features = VIRTIO_SEG_MAX;
    blk_state->block_cfg.max_seg        = QUEUE_SIZE - 2;
    // Virtio Block only uses one queue
    blk_state->queue.queue_size         = QUEUE_SIZE;


    blk_reset(blk_state);


    return 0;
}


static int 
connect_fn(struct v3_vm_info     * vm, 
	   void                  * frontend_data, 
	   struct v3_dev_blk_ops * ops, 
	   v3_cfg_tree_t         * cfg, 
	   void                  * private_data) 
{

    struct virtio_dev_state * virtio    = (struct virtio_dev_state *)frontend_data;
    struct virtio_blk_state * blk_state = (struct virtio_blk_state *)V3_Malloc(sizeof(struct virtio_blk_state));

    char * async_str = v3_cfg_val(cfg, "async");

    if (!blk_state) {
	PrintError("Cannot allocate in connect\n");
	return -1;
    }

    memset(blk_state, 0, sizeof(struct virtio_blk_state));


    if (async_str != NULL) {
	PrintDebug("async mode enabled\n");
	blk_state->async_enabled = atoi(async_str);
    }

    register_dev(virtio, blk_state);

    blk_state->ops                = ops;
    blk_state->backend_data       = private_data;
    blk_state->block_cfg.capacity = ops->get_capacity(private_data) / SECTOR_SIZE;

    PrintDebug("Virtio Capacity = %d -- 0x%p\n", 
	       (int)(blk_state->block_cfg.capacity), 
	       (void *)(addr_t)(blk_state->block_cfg.capacity));

    v3_spinlock_init(&blk_state->isr_lock);

    blk_state->shadow_used_idx  = 0;
    blk_state->shadow_avail_idx = 0;

    if (blk_state->async_enabled) {
        V3_Print("virtio-blk: creating IO thread\n");
        blk_state->async_thread = V3_CREATE_THREAD_ON_CPU(0, io_dispatcher, blk_state, "virtio-blkd");
    }

    return 0;
}


static int 
virtio_init(struct v3_vm_info * vm, 
	    v3_cfg_tree_t     * cfg) 
{
    struct virtio_dev_state * virtio_state = NULL;
    struct vm_device        * pci_bus      = v3_find_dev(vm, v3_cfg_val(cfg, "bus"));
    char                    * dev_id       = v3_cfg_val(cfg, "ID");


    PrintDebug("Initializing VIRTIO Block device\n");

    if (pci_bus == NULL) {
	PrintError("VirtIO devices require a PCI Bus");
	return -1;
    }


    virtio_state  = (struct virtio_dev_state *)V3_Malloc(sizeof(struct virtio_dev_state));

    if (!virtio_state) {
	PrintError("Cannot allocate in init\n");
	return -1;
    }



    memset(virtio_state, 0, sizeof(struct virtio_dev_state));

    INIT_LIST_HEAD(&(virtio_state->dev_list));
    virtio_state->pci_bus = pci_bus;


    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, virtio_state);

    if (dev == NULL) {
	PrintError("Could not attach device %s\n", dev_id);
	V3_Free(virtio_state);
	return -1;
    }

    if (v3_dev_add_blk_frontend(vm, dev_id, connect_fn, (void *)virtio_state) == -1) {
	PrintError("Could not register %s as block frontend\n", dev_id);
	v3_remove_device(dev);
	return -1;
    }

    return 0;
}


device_register("LNX_VIRTIO_BLK", virtio_init)
