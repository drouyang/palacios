/** 
 * PCI device interface code for passthrough PCI device
 * 
 * (c) 2013, Jack Lange <jacklange@cs.pitt.edu>
 * (c) 2013, Brian Kocoloski <briankoco@cs.pitt.edu>
 * (c) 2013, Jiannan Ouyang <briankoco@cs.pitt.edu>
 */

#include <lwk/spinlock.h>
#include <lwk/string.h>
#include <lwk/pci/pci.h>
#include <lwk/resource.h>
#include <lwk/waitq.h>
#include <lwk/interrupt.h>
#include <arch/uaccess.h>
#include <arch/proto.h>
#include <arch/pisces/pisces_lcall.h>
#include <arch/pisces/pisces.h>

#include "palacios.h"
#include "kitten-exts.h"


#include <interfaces/host_pci.h>



#define PCI_HDR_SIZE          256
#define PCI_DEVFN(slot, func) ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEV_NUM(devfn)    (((devfn) >> 3) & 0x1f)
#define PCI_FUNC_NUM(devfn)   ((devfn) & 0x07)

struct host_pci_device {
	char name[128];

	uint32_t num_vecs;
	uint32_t intx_ipi_vector;
	uint32_t msi_irq_vector;

	struct {
		u8 in_use;
		u8 iommu_enabled;
		
		u32 bus;
		u32 devfn;
		
		spinlock_t intx_lock;
		u8 intx_disabled;
		
		u32 num_msix_vecs;
		struct msix_entry * msix_entries;
		pci_dev_t * pci_dev;
	};

	struct v3_host_pci_dev v3_dev;
	void * v3_ctx;

	struct list_head dev_node;
};


struct pci_ack_irq_lcall {
	struct pisces_lcall lcall;
    
	char name[128];
	u32 vector;
} __attribute__((packed));

struct pci_cmd_lcall {
	struct pisces_lcall lcall;

	char name[128];
	host_pci_cmd_t cmd;
	u64 arg;
} __attribute__((packed));

struct pci_iommu_map_lcall {
	struct pisces_lcall lcall;

	char name[128];
	u64 region_start;
	u64 region_end;
	u64 gpa;
} __attribute__((packed));

struct pci_iommu_unmap_lcall {
	struct pisces_lcall lcall;

	char name[128];
	u64 region_start;
	u64 region_end;
	u64 gpa;
} __attribute__((packed));


struct pci_attach_lcall {
	struct pisces_lcall lcall;

	char name[128];
	u32  ipi_vector;
} __attribute__((packed));

struct pci_detach_lcall {
	struct pisces_lcall lcall;

	char name[128];
} __attribute__((packed));


static struct list_head  device_list;
static spinlock_t        lock;


static struct host_pci_device * 
find_dev_by_name(char * name)
{
	struct host_pci_device * dev = NULL;

	list_for_each_entry(dev, &device_list, dev_node) {
		if (strncmp(dev->name, name, 128) == 0) {
			return dev;
		}
	}

	return NULL;
}




static int 
host_pci_config_write(struct v3_host_pci_dev * v3_dev, 
		      u32                      reg_num,
		      void                   * src, 
		      u32                      length) 
{
	struct host_pci_device * host_dev = v3_dev->host_data;
	pci_dev_t              * pci_dev  = host_dev->pci_dev;
	u32 val = 0;

	memcpy(&val, src, length);
	pci_write(pci_dev, reg_num, length, val);

	return length;
}

static int
host_pci_config_read(struct v3_host_pci_dev * v3_dev, 
		     u32                      reg_num,
		     void                   * dst, 
		     u32                      length) 
{
	struct host_pci_device * host_dev = v3_dev->host_data;
	pci_dev_t              * pci_dev  = host_dev->pci_dev;
	u32 val = 0;

	val = pci_read(pci_dev, reg_num, length);
	memcpy(dst, &val, length);

	return length;
}

static int
host_pci_ack_irq(struct v3_host_pci_dev * v3_dev, 
		 unsigned int             vector) 
{
	struct host_pci_device   * host_dev   = v3_dev->host_data;
	struct pisces_lcall_resp * lcall_resp = NULL;
	struct pci_ack_irq_lcall   ack_irq_lcall;
	int status = 0;

	ack_irq_lcall.lcall.lcall    = PISCES_LCALL_PCI_ACK_IRQ;
	ack_irq_lcall.lcall.data_len = (sizeof(struct pci_ack_irq_lcall) -
					sizeof(struct pisces_lcall));
	ack_irq_lcall.vector         = vector;
	strncpy(ack_irq_lcall.name, host_dev->name, 128);
    
	status = pisces_lcall_exec((struct pisces_lcall       *)&ack_irq_lcall, 
				   (struct pisces_lcall_resp **)&lcall_resp);

	if (status != 0) {
		return -1;
	}

	status = lcall_resp->status;
	kmem_free(lcall_resp);

	return status;
}

static irqreturn_t
msi_irq_handler(int    irq,  
		void * dev_id)
{
	struct host_pci_device * host_dev = dev_id;

	if (irq != host_dev->msi_irq_vector) {
		return IRQ_NONE;
	}
	
	V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);
	
	return IRQ_HANDLED;
}

static irqreturn_t
msix_irq_handler(int    irq, 
		 void * dev_id)
{
	struct host_pci_device * host_dev = dev_id;
	int i;

	//printk("MSI-X IRQ Handler (%d)\n", vector);


	for (i = 0; i < host_dev->num_msix_vecs; i++) {

		if (irq == host_dev->msix_entries[i].vector) {
			V3_host_pci_raise_irq(&(host_dev->v3_dev), i);
			return IRQ_HANDLED;
		}
	}

	return IRQ_NONE;
}

static void 
disable_msix(struct host_pci_device * host_dev)
{
	int i = 0;
	
	printk("Disabling MSI-X\n");
	
	pci_msix_disable(host_dev->pci_dev);
	
	/* free allocated vectors */
	for (i = 0; i < host_dev->num_msix_vecs; i++) {
		irq_free(host_dev->msix_entries[i].vector, host_dev);
	}
	
	host_dev->num_msix_vecs = 0;
	kmem_free(host_dev->msix_entries);

	return;
}


static void 
disable_msi(struct host_pci_device * host_dev)
{
	/* free allocated vector number */
	
	pci_msi_disable(host_dev->pci_dev);
	irq_free(host_dev->msi_irq_vector, host_dev);
	
	host_dev->msi_irq_vector = 0;

	return;
}

static int 
host_pci_cmd(struct v3_host_pci_dev * v3_dev, 
	     host_pci_cmd_t           cmd, 
	     u64                      arg) 
{
	struct host_pci_device   * host_dev = v3_dev->host_data;
	struct pci_cmd_lcall       cmd_lcall;
	struct pisces_lcall_resp * cmd_lcall_resp = NULL;
	int status = 0;
	
	switch (cmd) {
	    case HOST_PCI_CMD_MSI_ENABLE: {
		    /* allocate MSI vector*/
		    /* only support 1 vector for now */
		    
		    int irq = -1;
		    
		    irq = irq_request_free_vector(msi_irq_handler, 0, "V3_HOST_PCI_MSI", host_dev);
		
		    if (irq == -1) {
			    printk(KERN_ERR "Could not allocate IRQ vector for host PCI device (%s)\n", host_dev->name);
			    return -1;
		    }
		    host_dev->msi_irq_vector = irq;
		
		    /* Enable MSI on the device */
		    pci_msi_setup(host_dev->pci_dev, irq);
		    pci_msi_enable(host_dev->pci_dev);
		
		    break;
	    }
	    case HOST_PCI_CMD_MSI_DISABLE:
		    disable_msi(host_dev);
		    break;
	    case HOST_PCI_CMD_MSIX_ENABLE: {
		    int i;
		
		    printk("Enabling MSI-X\n");
		
		    host_dev->num_msix_vecs = arg;
		    host_dev->msix_entries  = kmem_alloc(host_dev->num_msix_vecs * 
							 sizeof(struct msix_entry));
		
		    if (host_dev->msix_entries == NULL) {
			    printk("Error allocating MSI-X entries\n");
			    break;
		    }
		
		
		    for (i = 0; i < host_dev->num_msix_vecs; i++) {
			    int irq = -1;
			    struct msix_entry * msix_entry = &(host_dev->msix_entries[i]);
			
			    irq = irq_request_free_vector(msix_irq_handler, 0, "V3_HOST_PCI_MSIX", host_dev);
			
			    if (irq == -1) {
				    break;
			    }
			
			    msix_entry->entry  = i;
			    msix_entry->vector = irq;
		    }
		
		    /* Free allocated vectors if there's an error*/
		    if (i != host_dev->num_msix_vecs) {
			    int j = 0;
			
			    printk(KERN_ERR "Could not allocate %d MSIX vectors for Host PCI Device (%s)\n", 
				   host_dev->num_msix_vecs, host_dev->name);
			
			
			    for (j = 0; j < i; j++) {
				    irq_free(host_dev->msix_entries[j].vector, host_dev);
			    }
			
			    return -1;
		    }
		
		    /* Now we can enable MSIX on the device */
		    pci_msix_setup(host_dev->pci_dev, 
				   host_dev->msix_entries, 
				   host_dev->num_msix_vecs);
		
		    pci_msix_enable(host_dev->pci_dev);
		
		    break;
	    }
	    case HOST_PCI_CMD_MSIX_DISABLE: {
		    disable_msix(host_dev);
		    break;
	    }
	    case HOST_PCI_CMD_DMA_DISABLE: 
		    pci_dma_disable(host_dev->pci_dev);
		    break;
	    case HOST_PCI_CMD_DMA_ENABLE: 
		    pci_dma_enable(host_dev->pci_dev);
		    break;
	    case HOST_PCI_CMD_MEM_ENABLE: 
		    pci_mmio_enable(host_dev->pci_dev);
		    break;

	    case HOST_PCI_CMD_INTX_ENABLE:
	    case HOST_PCI_CMD_INTX_DISABLE:
		    cmd_lcall.lcall.lcall    = PISCES_LCALL_PCI_CMD;
		    cmd_lcall.lcall.data_len = (sizeof(struct pci_cmd_lcall) -
						sizeof(struct pisces_lcall));
		    cmd_lcall.cmd            = cmd;
		    cmd_lcall.arg            = arg;
		    strncpy(cmd_lcall.name, host_dev->name, 128);

		    /* forward pci cmd to Linux */
		    status = pisces_lcall_exec((struct pisces_lcall       *)&cmd_lcall,
					       (struct pisces_lcall_resp **)&cmd_lcall_resp);
		    if (status < 0) {
			    break;
		    }

		    status = cmd_lcall_resp->status;
		    kmem_free(cmd_lcall_resp);

		    break;
	    default:
		    printk(KERN_ERR "Invalid PCI command (%d) sent to host PCI interface, cmd\n", cmd);
		    break;
	}

	return status;
}


static struct v3_host_pci_dev * 
host_pci_request_dev(char * url, 
		     void * v3_ctx) 
{
	struct host_pci_device * host_dev = NULL;
	unsigned long flags;

	spin_lock_irqsave(&lock, flags);
	{
		host_dev = find_dev_by_name(url);
		
		if ((host_dev) && (host_dev->in_use == 0)) {
			host_dev->in_use = 1;	/* Mark the device as in use */
		} else {
			host_dev = NULL;
		}
	}
	spin_unlock_irqrestore(&lock, flags);

	if (host_dev == NULL) {
		printk(KERN_ERR "Could not find host device (%s)\n", url);
		return NULL;
	}


	/* Map device with IOMMU (Done in Linux via LCALLs) */
	{

		struct pci_iommu_map_lcall iommu_lcall;
		struct v3_guest_mem_region region;
		u64 gpa = 0;

		iommu_lcall.lcall.lcall    = PISCES_LCALL_IOMMU_MAP;
		iommu_lcall.lcall.data_len = (sizeof(struct pci_iommu_map_lcall) - 
					      sizeof(struct pisces_lcall));
		
		while (V3_get_guest_mem_region(v3_ctx, &region, gpa)) {
			
			struct pisces_lcall_resp * lcall_resp = NULL;
			int status = 0;
				
			printk("Memory region (GPA:%p), start=%p, end=%p\n",
			       (void *)gpa,
			       (void *)region.start,
			       (void *)region.end);

			strncpy(iommu_lcall.name, host_dev->name, 128);
			iommu_lcall.region_start = region.start;
			iommu_lcall.region_end   = region.end;
			iommu_lcall.gpa          = gpa;
			
			pisces_lcall_exec((struct pisces_lcall       *)&iommu_lcall,
					  (struct pisces_lcall_resp **)&lcall_resp);
			
			status = lcall_resp->status;
			kmem_free(lcall_resp);

			if (status != 0) {
				return NULL;
			}
			
			gpa += (region.end - region.start);
		}
	}


	/* Attach Device */
	{
		struct pci_attach_lcall    attach_lcall;
		struct pisces_lcall_resp * lcall_resp = NULL;
		int status = 0;

		/* Setup LCALL Fields */
		attach_lcall.lcall.lcall    = PISCES_LCALL_PCI_ATTACH;
		attach_lcall.lcall.data_len = (sizeof(struct pci_attach_lcall) - 
					       sizeof(struct pisces_lcall));
		strncpy(attach_lcall.name, host_dev->name, 128);
		attach_lcall.ipi_vector     = host_dev->intx_ipi_vector;

		/* Issue LCALL to Linux */
		pisces_lcall_exec((struct pisces_lcall       *)&attach_lcall,
				  (struct pisces_lcall_resp **)&lcall_resp);

		status = lcall_resp->status;
		kmem_free(lcall_resp);
		
		if (status != 0) {
			return NULL;
		}
	}

	host_dev->v3_ctx = v3_ctx;

	return &(host_dev->v3_dev);
}


static int 
host_pci_release_dev(struct v3_host_pci_dev * v3_dev) 
{
	struct host_pci_device   * host_dev   = v3_dev->host_data;
	int status = 0;
	
	pci_dma_disable(host_dev->pci_dev);

	/* Disable Any Active IRQs */

	if (host_dev->num_msix_vecs > 0) {
		disable_msix(host_dev);
	} else if (host_dev->msi_irq_vector > 0) {
		disable_msi(host_dev);
	} else {
		struct pci_cmd_lcall       cmd_lcall;
		struct pisces_lcall_resp * cmd_lcall_resp = NULL;

		cmd_lcall.lcall.lcall    = PISCES_LCALL_PCI_CMD;
		cmd_lcall.lcall.data_len = (sizeof(struct pci_cmd_lcall) -
					    sizeof(struct pisces_lcall));
		cmd_lcall.cmd            = HOST_PCI_CMD_INTX_DISABLE;
		cmd_lcall.arg            = 0;
		strncpy(cmd_lcall.name, host_dev->name, 128);
		
		/* forward pci cmd to Linux */
		status = pisces_lcall_exec((struct pisces_lcall       *)&cmd_lcall,
					   (struct pisces_lcall_resp **)&cmd_lcall_resp);
		if (status < 0) {
			return -1;
		}
		
		status = cmd_lcall_resp->status;
		kmem_free(cmd_lcall_resp);
	}


	/* Unmap IOMMU */
	{

		struct pci_iommu_unmap_lcall iommu_lcall;
		struct v3_guest_mem_region region;
		u64 gpa = 0;

		iommu_lcall.lcall.lcall    = PISCES_LCALL_IOMMU_UNMAP;
		iommu_lcall.lcall.data_len = (sizeof(struct pci_iommu_unmap_lcall) - 
					      sizeof(struct pisces_lcall));
		
		while (V3_get_guest_mem_region(host_dev->v3_ctx, &region, gpa)) {
			
			struct pisces_lcall_resp * lcall_resp = NULL;
			int status = 0;
				
			printk("Unmapping Memory region (GPA:%p), start=%p, end=%p\n",
			       (void *)gpa,
			       (void *)region.start,
			       (void *)region.end);

			strncpy(iommu_lcall.name, host_dev->name, 128);
			iommu_lcall.region_start = region.start;
			iommu_lcall.region_end   = region.end;
			iommu_lcall.gpa          = gpa;
			
			pisces_lcall_exec((struct pisces_lcall       *)&iommu_lcall,
					  (struct pisces_lcall_resp **)&lcall_resp);
			
			status = lcall_resp->status;
			kmem_free(lcall_resp);

			if (status != 0) {
				return -1;
			}
			
			gpa += (region.end - region.start);
		}
	}


	/* Detach from IOMMU */

	{
		struct pci_detach_lcall    detach_lcall;
		struct pisces_lcall_resp * lcall_resp = NULL;
		int status = 0;

		/* Setup LCALL Fields */
		detach_lcall.lcall.lcall    = PISCES_LCALL_PCI_DETACH;
		detach_lcall.lcall.data_len = (sizeof(struct pci_detach_lcall) - 
					       sizeof(struct pisces_lcall));
		strncpy(detach_lcall.name, host_dev->name, 128);

		/* Issue LCALL to Linux */
		pisces_lcall_exec((struct pisces_lcall       *)&detach_lcall,
				  (struct pisces_lcall_resp **)&lcall_resp);

		status = lcall_resp->status;
		kmem_free(lcall_resp);
		
		if (status != 0) {
			return -1;
		}
	}


	/* Mark device as free */
	__asm__ __volatile__ ("":::"memory");
	host_dev->in_use = 0;

	return 0;
}


static struct v3_host_pci_hooks host_pci_hooks = {
	.request_device = host_pci_request_dev,
	.release_device = host_pci_release_dev,
	.config_write   = host_pci_config_write,
	.config_read    = host_pci_config_read,
	.ack_irq        = host_pci_ack_irq,
	.pci_cmd        = host_pci_cmd,
};


static irqreturn_t
intx_ipi_handler(int    irq, 
		 void * dev_id)
{
	struct host_pci_device * host_dev = dev_id;

	//   printk("Received PCI INTx IPI (vector=%u)\n", vector);

	if (irq != host_dev->intx_ipi_vector) {
		return IRQ_NONE;
	}


	V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);
	
	return IRQ_HANDLED;
}


static int 
host_pci_setup_dev(struct host_pci_device * host_dev)
{
	struct v3_host_pci_dev * v3_dev = &(host_dev->v3_dev);
	pci_dev_t              * dev    = NULL;
 

	dev = pci_get_dev_bus_and_slot(host_dev->bus,
				       host_dev->devfn);

	if (dev == NULL) {
		printk("Could not find HW pci device (bus=%d, devfn=%d)\n",
		       host_dev->bus, host_dev->devfn);
		return -1;
	}

	// record pointer in dev state
	host_dev->pci_dev           = dev;
	host_dev->intx_disabled = 1;

	spin_lock_init(&(host_dev->intx_lock));

	// -- Device initialization already setup on the Linux side
     
	// decode and cache BAR registers
	// cache first 6 BAR regs */
	{
		int i = 0;
		for (i = 0; i < 6; i++) {
			struct v3_host_pci_bar * bar = &(v3_dev->bars[i]);
			pci_bar_t pci_bar;

			pcicfg_bar_decode(&dev->cfg, i, &pci_bar);


			if (pci_bar.address == 0) {

				bar->type         = PT_BAR_NONE;

			} else if (pci_bar.mem == PCIM_BAR_MEM_SPACE) {

				bar->size         = pci_bar.size;
				bar->addr         = pci_bar.address;
				bar->prefetchable = (pci_bar.prefetch != 0);

				// TODO: figure out how to set this
				bar->cacheable    = 0;

				if (pci_bar.type == 2) {

					bar->type = PT_BAR_MEM64_LO;

					{
						struct v3_host_pci_bar * hi_bar = &(v3_dev->bars[++i]);

						hi_bar->type         = PT_BAR_MEM64_HI;
						hi_bar->size         = pci_bar.size;
						hi_bar->addr         = pci_bar.address;
						hi_bar->prefetchable = (pci_bar.prefetch != 0);

						// TODO: figure out how to set this
						hi_bar->cacheable    = 0;
					}
				}  else if (pci_bar.type == 1) {
					bar->type = PT_BAR_MEM24;
				} else {
					bar->type = PT_BAR_MEM32;
				}
			} else {
				bar->type = PT_BAR_IO;
				bar->size = pci_bar.size;
				bar->addr = pci_bar.address;
			}

			printk("Caching pci bar region %d (%p --> %p)\n",
			       i,
			       (void *)bar->addr,
			       (void *)(bar->addr + bar->size));
		} 
	}



	// Cache Expansion ROM
	{
		pci_exp_rom_bar_t rom_bar;
		pcicfg_exp_rom_decode(&dev->cfg, &rom_bar);

		v3_dev->exp_rom.size            = rom_bar.size;
		v3_dev->exp_rom.addr            = rom_bar.address;
		v3_dev->exp_rom.type            = PT_EXP_ROM;
		v3_dev->exp_rom.exp_rom_enabled = rom_bar.enable;

	}

	// cache configuration space
	{ 
		int i = 0;
		for (i = 0; i < PCI_HDR_SIZE; i += 4) {
			*(u32 *)&v3_dev->cfg_space[i] = pci_read(dev, i, 4);
		}
	}

    
	// reserve device IRQ vector for IPI
	{
		int irq = irq_request_free_vector(intx_ipi_handler, 0, "V3_HOST_PCI_IPI", host_dev);

		if (irq == -1) {
			printk(KERN_ERR "Could not allocate IPI vector for V3 Host PCI device (%s)\n",
			       host_dev->name);
			return -1;
		}

		host_dev->intx_ipi_vector = irq;
	}


	return 0;
}


static int 
register_pci_hw_dev(unsigned int  cmd, 
		    unsigned long arg)
{
	void __user            * argp         = (void __user *)arg;
	struct host_pci_device * host_dev     = NULL;
	struct v3_hw_pci_dev     pci_dev_arg;

	unsigned long flags = 0;
	int           ret   = 0;

	if (copy_from_user(&pci_dev_arg, argp, sizeof(struct v3_hw_pci_dev))) {
		printk("%s(%d): copy from user error...\n", __FILE__, __LINE__);
		return -EFAULT;
	}

	host_dev = kmem_alloc(sizeof(struct host_pci_device));
	memset(host_dev, 0, sizeof(struct host_pci_device));

	printk("registering host device %s\n",
	       pci_dev_arg.name);
	printk("Bus=%d, device=%d, function=%d\n", 
	       pci_dev_arg.bus, 
	       pci_dev_arg.dev,
	       pci_dev_arg.func);

	strncpy(host_dev->name, pci_dev_arg.name, 128);
	host_dev->v3_dev.host_data = host_dev;


	host_dev->bus   = pci_dev_arg.bus;
	host_dev->devfn = PCI_DEVFN(pci_dev_arg.dev, pci_dev_arg.func);


	if (!find_dev_by_name(pci_dev_arg.name)) {
		spin_lock_irqsave(&lock, flags);
		{
			list_add(&(host_dev->dev_node), &device_list);
		}
		spin_unlock_irqrestore(&lock, flags);
	} else {
		// Error device already exists
		printk(KERN_ERR "Error: Device %s is already registered\n", pci_dev_arg.name);
		kmem_free(host_dev);
		return -EFAULT;
	}

	ret = host_pci_setup_dev(host_dev);
	if (ret == -1) {
		printk(KERN_ERR "Could not setup pci device\n");
		return -1;
	}

	printk("Device %s registered\n", pci_dev_arg.name);

	/* We use the ioctl return value to signal the ipi vector to user space */
	return host_dev->intx_ipi_vector;
}



static int
host_pci_init( void ) 
{
	INIT_LIST_HEAD(&device_list);
	spin_lock_init(&lock);

	V3_Init_Host_PCI(&host_pci_hooks);

	add_global_ctrl(V3_ADD_PCI, register_pci_hw_dev);

	return 0;
}



static struct kitten_ext host_pci_ext = {
	.name         = "HOST_PCI",
	.init         = host_pci_init,
	.deinit       = NULL,
	.guest_init   = NULL,
	.guest_deinit = NULL
};


register_extension(&host_pci_ext);
