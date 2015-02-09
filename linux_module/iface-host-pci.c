/* Host PCI interface 
 *  (c) Jack Lange, 2012
 *  jacklange@cs.pitt.edu 
 */

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/version.h>

#include "palacios.h"
#include "linux-exts.h"
#include "mm.h"

#include <interfaces/host_pci.h>

#define PCI_HDR_SIZE 256


static struct list_head device_list;
static spinlock_t       lock;

struct pci_dev;
struct iommu_domain;

struct host_pci_device {
    char name[128];

    u8 in_use;


    struct {    
	u8 iommu_enabled;
	
	u32 bus;
	u32 devfn;
	
	spinlock_t intx_lock;
	u8         intx_disabled;
	
	u32                   num_msix_vecs;
	struct msix_entry   * msix_entries;
	struct iommu_domain * iommu_domain;
	
	struct pci_dev * dev; 
    } hw_dev;
    

    struct v3_host_pci_dev v3_dev;
    void * v3_ctx;



    struct list_head dev_node;
};


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





static irqreturn_t 
host_pci_intx_irq_handler(int    irq, 
			  void * priv_data) 
{
    struct host_pci_device * host_dev = priv_data;

    //   printk("Host PCI IRQ handler (%d)\n", irq);

    spin_lock(&(host_dev->hw_dev.intx_lock));
    {
	disable_irq_nosync(irq);
	host_dev->hw_dev.intx_disabled = 1;
    }
    spin_unlock(&(host_dev->hw_dev.intx_lock));

    V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);

    return IRQ_HANDLED;
}



static irqreturn_t 
host_pci_msi_irq_handler(int    irq, 
			 void * priv_data)
{
    struct host_pci_device * host_dev = priv_data;
    // printk(KERN_ERR "Host PCI MSI IRQ Handler (%d)\n", irq);

    V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);

    return IRQ_HANDLED;
}

static irqreturn_t 
host_pci_msix_irq_handler(int    irq, 
			  void * priv_data) 
{
    struct host_pci_device * host_dev = priv_data;
    int i = 0;
    
    //    printk("Host PCI MSIX IRQ Handler (%d)\n", irq);
    
    // find vector index
    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
        if (irq == host_dev->hw_dev.msix_entries[i].vector) {
            V3_host_pci_raise_irq(&(host_dev->v3_dev), i);
        }    
    }

    return IRQ_HANDLED;
}


static irqreturn_t 
host_pci_msix_irq_handler_thread(int    irq, 
				 void * priv_data) 
{
    struct host_pci_device * host_dev = priv_data;
    int i = 0;

    v3_lnx_printk("Host PCI MSIX IRQ threaded handler (%d)\n", irq);

    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
        if (irq == host_dev->hw_dev.msix_entries[i].vector) {
            V3_host_pci_raise_irq(&(host_dev->v3_dev), i);
        }
    }

    return IRQ_HANDLED;
}


static struct v3_host_pci_dev * 
request_pci_dev(char * url, 
		void * v3_ctx) 
{   
    struct host_pci_device * host_dev = NULL;
    unsigned long flags;
    int acquired = 0;

    spin_lock_irqsave(&lock, flags);
    {
	host_dev = find_dev_by_name(url);
	
	if ( (host_dev         != NULL) && 
	     (host_dev->in_use == 0) ) {

	    host_dev->in_use = 1;
	    acquired         = 1;
	}
    }
    spin_unlock_irqrestore(&lock, flags);
    
    if (host_dev == NULL) {
	ERROR("Could not locate requested host PCI device (%s)\n", url);
	return NULL;
    } else if (acquired == 0) {
	ERROR("Host PCI Device (%s) already reserved\n", url);
	return NULL;
    }

    host_dev->v3_ctx = v3_ctx;

    {
	struct v3_host_pci_dev * v3_dev = &(host_dev->v3_dev);
	struct pci_dev         * dev    = host_dev->hw_dev.dev;
	int ret = 0;
	
	
	dev = pci_get_bus_and_slot(host_dev->hw_dev.bus,
				   host_dev->hw_dev.devfn);
	
	
	if (dev == NULL) {
	    ERROR("Could not find HW pci device (bus=%d, devfn=%d)\n", 
		  host_dev->hw_dev.bus, host_dev->hw_dev.devfn); 
	    return NULL;
	}
	
	// record pointer in dev state
	host_dev->hw_dev.dev           = dev;
	host_dev->hw_dev.intx_disabled = 1;
	spin_lock_init(&(host_dev->hw_dev.intx_lock));
	
	if (pci_enable_device(dev)) {
	    ERROR("Could not enable Device\n");
	    return NULL;
	}
	
	ret = pci_request_regions(dev, "v3vee");
	if (ret != 0) {
	    ERROR("Could not reservce PCI regions\n");
	    return NULL;
	}
	
	
	pci_reset_function(host_dev->hw_dev.dev);
	pci_save_state(host_dev->hw_dev.dev);
	
	
	/* Cache first 6 BAR regs */
	{
	    int i = 0;
	    
	    for (i = 0; i < 6; i++) {
		struct v3_host_pci_bar * bar = &(v3_dev->bars[i]);
		unsigned long flags;
		
		bar->size = pci_resource_len(dev, i);
		bar->addr = pci_resource_start(dev, i);
		flags     = pci_resource_flags(dev, i);
		
		if (flags & IORESOURCE_IO) {
		    bar->type = PT_BAR_IO;
		} else if (flags & IORESOURCE_MEM) {
		    if (flags & IORESOURCE_MEM_64) {
			struct v3_host_pci_bar * hi_bar = &(v3_dev->bars[i + 1]); 
			
			bar->type            = PT_BAR_MEM64_LO;
			
			hi_bar->type         = PT_BAR_MEM64_HI;
			hi_bar->size         = bar->size;
			hi_bar->addr         = bar->addr;
			hi_bar->cacheable    = ((flags & IORESOURCE_CACHEABLE) != 0);
			hi_bar->prefetchable = ((flags & IORESOURCE_PREFETCH) != 0);
			
			i++;
		    } else if (flags & IORESOURCE_DMA) {
			bar->type            = PT_BAR_MEM24;
		    } else {
			bar->type            = PT_BAR_MEM32;
		    }
		    
		    bar->cacheable    = ((flags & IORESOURCE_CACHEABLE) != 0);
		    bar->prefetchable = ((flags & IORESOURCE_PREFETCH)  != 0);
		    
		} else {
		    bar->type         = PT_BAR_NONE;
		}
	    }
	}
	
	/* Cache expansion rom bar */
	{
	    struct resource * rom_res  = &(dev->resource[PCI_ROM_RESOURCE]);
	    int               rom_size = pci_resource_len(dev, PCI_ROM_RESOURCE);
	    
	    if (rom_size > 0) {
		unsigned long flags;
		
		v3_dev->exp_rom.size            = rom_size;
		v3_dev->exp_rom.addr            = pci_resource_start(dev, PCI_ROM_RESOURCE);
		flags                           = pci_resource_flags(dev, PCI_ROM_RESOURCE);
		v3_dev->exp_rom.type            = PT_EXP_ROM;
		v3_dev->exp_rom.exp_rom_enabled = rom_res->flags & IORESOURCE_ROM_ENABLE;
		
		v3_lnx_printk("%s: exp_rom enabled: %d\n",
			      host_dev->name,
			      v3_dev->exp_rom.exp_rom_enabled);
	    }
	    
	}
	
	/* Cache entire configuration space */
	{
	    int m = 0;
	    
	    // Copy the configuration space to the local cached version
	    for (m = 0; m < PCI_HDR_SIZE; m += 4) {
		pci_read_config_dword(dev, m, (u32 *)&(v3_dev->cfg_space[m]));
	    }
	}
	
	
	
	if (v3_dev->iface == IOMMU) {
	    struct v3_guest_mem_region * regs = NULL;
	    uintptr_t gpa      = 0;
	    int       flags    = 0;
	    int       num_regs = 0;
	    int       map_ret  = 0;
	    int       i        = 0;
	    
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,43)
	    host_dev->hw_dev.iommu_domain = iommu_domain_alloc();
#else 
	    host_dev->hw_dev.iommu_domain = iommu_domain_alloc(&pci_bus_type);
#endif
	    
	    if (host_dev->hw_dev.iommu_domain == NULL) {
		ERROR("IOMMU ERROR: Could not allocate domain\n");
		return NULL;
	    }
	    
	    
	    if (iommu_attach_device(host_dev->hw_dev.iommu_domain, &(dev->dev))) {
		ERROR("ERROR attaching host PCI device to IOMMU domain\n");
		return NULL;
	    }
	    
	    
	    flags = IOMMU_READ | IOMMU_WRITE; // Need to see what IOMMU_CACHE means
	    
	    // Disable this for now, because it causes Intel DMAR faults for invalid bits set in PTE
	    if (iommu_domain_has_cap(host_dev->hw_dev.iommu_domain, IOMMU_CAP_CACHE_COHERENCY)) {
		v3_lnx_printk("IOMMU SUPPORTS CACHE COHERENCY FOR DMA REMAPPING\n");
		flags |= IOMMU_CACHE;
	    }
	    
	    
	    regs = v3_get_guest_memory_regions(v3_ctx, &num_regs);

	    
	    for (i = 0; i < num_regs; i++) {
		v3_lnx_printk("Memory region: (GPA=%p), start=%p, end=%p\n", 
			      (void *)gpa, 
			      (void *)regs[i].start,
			      (void *)regs[i].end);


	    
	
		/* This version could be wrong */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) 
		// Guest VAs start at zero and go to end of memory
		iommu_map_range(host_dev->hw_dev.iommu_domain, 0, regs[i].start, (regs[i].end - regs[i].start), flags);
#else 
		/* Linux actually made the interface worse... Now you can only map memory in powers of 2 (meant to only be pages...) */
		{	
		    u64 size      = regs[i].end - regs[i].start;
		    u32 page_size = 512 * 4096; // assume large 64bit pages (2MB)
		    u64 hpa       = regs[i].start;
		

		    v3_lnx_printk("Memory region: GPA=%p, HPA=%p, size=%p\n", 
				  (void *)gpa, 
				  (void *)hpa,
				  (void *)size);


		    do {
			if (size < page_size) {
			    page_size = 4096; // less than a 2MB granularity, so we switch to small pages (4KB)
			}

			//  printk("Mapping IOMMU region gpa=%p hpa=%p (size=%d)\n", (void *)gpa, (void *)hpa, page_size);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,43)

			if (iommu_map(host_dev->hw_dev.iommu_domain, gpa, hpa, 
				      get_order(page_size), flags)) {

			    ERROR("Could not map sub region (GPA=%p) (HPA=%p) (order=%d)\n", 
				  (void *)gpa, 
				  (void *)hpa, 
				  get_order(page_size));

			    break;
			}
#else 
			// JRL: Linux Cannot decide whether they want to specify mappings by order or by page size. So now we're back to page size.

			if (iommu_map(host_dev->hw_dev.iommu_domain, gpa, hpa, 
				      page_size, flags)) {

			    ERROR("Could not map sub region (GPA=%p) (HPA=%p) (size=%d)\n", 
				  (void *)gpa, 
				  (void *)hpa, 
				  get_order(page_size));

			    break;
			}
#endif
		    
			hpa  += page_size;
			gpa  += page_size;
		    
			size -= page_size;

		    } while (size > 0);
		}
#endif

	    }

	    palacios_kfree(regs);
	    
	    if (map_ret == -1) {
		ERROR("Could not Map PCI device into IOMMU: NEED TO CLEANUP THE STATE\n");
		return NULL;
	    }


	    if (iommu_domain_has_cap(host_dev->hw_dev.iommu_domain, IOMMU_CAP_INTR_REMAP)) {
		v3_lnx_printk("IOMMU SUPPORTS INTERRUPT REMAPPING\n");
	    }

	    dev->dev_flags |= PCI_DEV_FLAGS_ASSIGNED;
	

	}



	/* Currently broken because PIIX4 support is not yet working     */

	v3_lnx_printk("Requesting Threaded IRQ handler for IRQ %d\n", dev->irq);

	//    setup regular IRQs until advanced IRQ mechanisms are enabled
	if (request_threaded_irq(dev->irq, NULL, host_pci_intx_irq_handler, 
				 IRQF_ONESHOT, "V3Vee_Host_PCI_INTx", (void *)host_dev)) {

	    ERROR("Could not assign IRQ to host PCI device (%s)\n", host_dev->name);
	}

	host_dev->hw_dev.intx_disabled = 0;


    }




    return &(host_dev->v3_dev);
}


static int 
release_pci_dev(struct v3_host_pci_dev * v3_dev) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pci_dev         * dev      = host_dev->hw_dev.dev;
    

    /* Disable DMA operations, because we are going to nuke the IOMMU state  */
    pci_clear_master(dev);    

    /* Free MSIX IRQs if enabled */
    if (dev->msix_enabled) {
	int i = 0;
	
	for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
	    disable_irq(host_dev->hw_dev.msix_entries[i].vector);
	}

	for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
	    free_irq(host_dev->hw_dev.msix_entries[i].vector, (void *)host_dev);
	}

	host_dev->hw_dev.num_msix_vecs = 0;
	palacios_kfree(host_dev->hw_dev.msix_entries);

	pci_disable_msix(dev);
    }
    
    /* Disable MSI IRQs if enabled */
    if (dev->msi_enabled) {
	disable_irq(dev->irq);
	free_irq(dev->irq, (void *)host_dev);
	pci_disable_msi(dev);
    }

    /* Disable Legacy IRQs if enabled */
    if (!host_dev->hw_dev.intx_disabled) {
	disable_irq(dev->irq);
	free_irq(dev->irq, (void *)host_dev);

	host_dev->hw_dev.intx_disabled = 1;
    }

    /* Free BAR regions */
    pci_release_regions(dev);
    
    /* Reset Device State */
    pci_reset_function(dev);

    /* Unmap Device from IOMMU */
    if (v3_dev->iface == IOMMU) {
	struct v3_guest_mem_region * regs = NULL;

	int       num_regs = 0;
	uintptr_t gpa      = 0;
	int       i        = 0;

	
	regs = v3_get_guest_memory_regions(host_dev->v3_ctx, &num_regs);


	for (i = 0; i < num_regs; i++) {
	    u64 size      = regs[i].end - regs[i].start;
	    u32 page_size = 512 * 4096;


	    do {
		if (size < page_size) {
		    page_size = 4096;
		}
		    
		iommu_unmap(host_dev->hw_dev.iommu_domain, gpa, page_size);
		    
		gpa  += page_size;
		size -= page_size;
		    
	    } while (size > 0);
	}

	palacios_kfree(regs);

	/* Free IOMMU domain */
	iommu_detach_device(host_dev->hw_dev.iommu_domain, &(dev->dev));
	iommu_domain_free(host_dev->hw_dev.iommu_domain);
    }

    
    pci_restore_state(dev);
    pci_disable_device(dev);


    /* Mark device as available */
    host_dev->in_use = 0;


    host_dev->v3_ctx = NULL;

    return 0;
}


static int
host_pci_config_write(struct v3_host_pci_dev * v3_dev, 
		      unsigned int             reg, 
		      void                   * src, 
		      unsigned int             length)
{
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pci_dev         * dev      = host_dev->hw_dev.dev;

    if (reg < 64) {
	return 0;
    }
	
    if (length == 1) {
	pci_write_config_byte(dev,  reg, *(u8  *)src);
    } else if (length == 2) {
	pci_write_config_word(dev,  reg, *(u16 *)src);
    } else if (length == 4) {
	pci_write_config_dword(dev, reg, *(u32 *)src);
    } else {
	ERROR("Invalid length of host PCI config update\n");
	return -1;
    }

    return 0;
}

static int 
host_pci_config_read(struct v3_host_pci_dev * v3_dev,
		     unsigned int             reg, 
		     void                   * dst, 
		     unsigned int             length)
{
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pci_dev         * dev      = host_dev->hw_dev.dev;
	
    if (length == 1) {
	pci_read_config_byte(dev,  reg, dst);
    } else if (length == 2) {
	pci_read_config_word(dev,  reg, dst);
    } else if (length == 4) {
	pci_read_config_dword(dev, reg, dst);
    } else {
	ERROR("Invalid length of host PCI config read\n");
	return -1;
    }

    return 0;
}





static int
host_pci_ack_irq(struct v3_host_pci_dev * v3_dev, 
		 unsigned int             vector) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pci_dev         * dev      = host_dev->hw_dev.dev;
    unsigned long flags;

    //    printk("Acking IRQ vector %d\n", vector);

    spin_lock_irqsave(&(host_dev->hw_dev.intx_lock), flags);
    {
	//    printk("Enabling IRQ %d\n", dev->irq);
	enable_irq(dev->irq);
	host_dev->hw_dev.intx_disabled = 0;
    }
    spin_unlock_irqrestore(&(host_dev->hw_dev.intx_lock), flags);
    
    return 0;
}



static int 
host_pci_cmd(struct v3_host_pci_dev * v3_dev, 
	     host_pci_cmd_t           cmd,
	     u64                      arg) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pci_dev         * dev      = host_dev->hw_dev.dev;

    switch (cmd) {
	case HOST_PCI_CMD_DMA_DISABLE:
	    v3_lnx_printk("Passthrough PCI device disabling BMDMA\n");
	    pci_clear_master(host_dev->hw_dev.dev);
	    break;
	case HOST_PCI_CMD_DMA_ENABLE:
	    v3_lnx_printk("Passthrough PCI device Enabling BMDMA\n");
	    pci_set_master(host_dev->hw_dev.dev);
	    break;
	case HOST_PCI_CMD_MEM_ENABLE:{
	    uint16_t hw_cmd = 0;

	    v3_lnx_printk("Passthrough PCI device enabling MEM resources\n");
	    
	    pci_read_config_word(host_dev->hw_dev.dev,  PCI_COMMAND, &hw_cmd);
	    hw_cmd |= 0x2;
	    pci_write_config_word(host_dev->hw_dev.dev, PCI_COMMAND,  hw_cmd);


	    break;
	}
	case HOST_PCI_CMD_INTX_DISABLE:
	    v3_lnx_printk("Passthrough PCI device disabling INTx IRQ\n");

	    disable_irq(dev->irq);
	    free_irq(dev->irq, (void *)host_dev);

	    break;
	case HOST_PCI_CMD_INTX_ENABLE:
	    v3_lnx_printk("Passthrough PCI device Enabling INTx IRQ\n");
	
	    if (request_threaded_irq(dev->irq, NULL, host_pci_intx_irq_handler, 
				     IRQF_ONESHOT, "V3Vee_Host_PCI_INTx", (void *)host_dev)) {
		ERROR("Could not assign IRQ to host PCI device (%s)\n", host_dev->name);
	    }

	    break;

	case HOST_PCI_CMD_MSI_DISABLE:
	    v3_lnx_printk("Passthrough PCI device Disabling MSIs\n");

	    disable_irq(dev->irq);
	    free_irq(dev->irq, (void *)host_dev);

	    pci_disable_msi(dev);

	    break;
	case HOST_PCI_CMD_MSI_ENABLE:

	    v3_lnx_printk(KERN_ERR "Passthrough PCI device Enabling MSI\n");

	    if (!dev->msi_enabled) {

		v3_lnx_printk("Enabling MSI\n");

		if (pci_enable_msi(dev) != 0) {
		    ERROR("Error enabling MSI for host device %s\n", host_dev->name);
		    return -1;
		}
	    }

	    
	    v3_lnx_printk("MSI Has been Enabled\n");

	    if (request_irq(dev->irq, host_pci_msi_irq_handler, 
			    0, "V3Vee_host_PCI_MSI", (void *)host_dev)) {
		ERROR("Error Requesting IRQ %d for Passthrough MSI IRQ\n", dev->irq);
		pci_disable_msi(dev);
		return -1;
	    }

	    v3_lnx_printk("IRQ requested\n");

	    break;
	case HOST_PCI_CMD_MSIX_ENABLE: {
	    int i   = 0;
	    int ret = 0;
        
	    v3_lnx_printk("Passthrough PCI device Enabling MSIX (%llu entries requested)\n", arg);


	    host_dev->hw_dev.num_msix_vecs = arg;
	    host_dev->hw_dev.msix_entries  = kzalloc((sizeof(struct msix_entry) * host_dev->hw_dev.num_msix_vecs), 
						     GFP_KERNEL);
        
	    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
		host_dev->hw_dev.msix_entries[i].entry = i;
	    }

	    ret = pci_enable_msix(dev, host_dev->hw_dev.msix_entries, 
				  host_dev->hw_dev.num_msix_vecs);

	    if (ret != 0) {
		ERROR("Error: failed to enable pci msix. ret = %d\n", ret);
		kfree(host_dev->hw_dev.msix_entries);
		host_dev->hw_dev.num_msix_vecs = 0;
		return -1;
	    }


	    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
		if (request_threaded_irq(host_dev->hw_dev.msix_entries[i].vector, 
					 host_pci_msix_irq_handler, 
					 host_pci_msix_irq_handler_thread, 
					 0, 
					 "V3VEE_host_PCI_MSIX", 
					 (void *)host_dev)) {

		   ERROR("Error requesting IRQ %d for Passthrough MSIX IRQ\n", 
			   host_dev->hw_dev.msix_entries[i].vector);
		}
	    }

	    break;
	}

	case HOST_PCI_CMD_MSIX_DISABLE: {
	    int i = 0;

	    v3_lnx_printk("Passthrough PCI device Disabling MSIX\n");
	    
	    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
		disable_irq(host_dev->hw_dev.msix_entries[i].vector);
	    }

	    for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
		free_irq(host_dev->hw_dev.msix_entries[i].vector, (void *)host_dev);
	    }

	    host_dev->hw_dev.num_msix_vecs = 0;
	    palacios_kfree(host_dev->hw_dev.msix_entries);

	    pci_disable_msix(dev);

	    break;
	}
	default:
	    ERROR("Error: unhandled passthrough PCI command: %d\n", cmd);
	    return -1;
	   
    }

    return 0;
    
}

static struct v3_host_pci_hooks pci_hooks = {
    .request_device  = request_pci_dev,
    .release_device  = release_pci_dev,
    .config_write    = host_pci_config_write,
    .config_read     = host_pci_config_read,
    .ack_irq         = host_pci_ack_irq,
    .pci_cmd         = host_pci_cmd,

};



static int 
register_pci_hw_dev(unsigned int  cmd,
		    unsigned long arg) 
{
    void __user            * argp     = (void __user *)arg;
    struct host_pci_device * host_dev = NULL;

    struct v3_hw_pci_dev  hw_dev_arg;
    unsigned long flags;
    bool iommu_avail = false;
    int  ret = 0;

    if (copy_from_user(&hw_dev_arg, argp, sizeof(struct v3_hw_pci_dev))) {
	ERROR("copy from user error...\n");
	return -EFAULT;
    }

    host_dev = palacios_kmalloc(sizeof(struct host_pci_device), GFP_KERNEL);

    if (IS_ERR(host_dev)) {
	ERROR("Error: Could not allocate host PCI device for (%s)\n", hw_dev_arg.name);
	return -1;
    }

    memset(host_dev, 0, sizeof(struct host_pci_device));

    host_dev->v3_dev.host_data = host_dev;
    host_dev->hw_dev.bus       = hw_dev_arg.bus;
    host_dev->hw_dev.devfn     = PCI_DEVFN(hw_dev_arg.dev, hw_dev_arg.func);
    strncpy(host_dev->name, hw_dev_arg.name, 128);
    

    spin_lock_irqsave(&lock, flags);
    {
	if (!find_dev_by_name(hw_dev_arg.name)) {
	    list_add(&(host_dev->dev_node), &device_list);
	    ret = 1;
	}
    }
    spin_unlock_irqrestore(&lock, flags);

    if (ret == 0) {
	// Error device already exists
	ERROR("Registering a duplicate device (%s)\n", host_dev->name);
	palacios_kfree(host_dev);
	return -EFAULT;
    }

    


	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,43)
    //JRL: This version might not be correct...
    iommu_avail = iommu_found();
#else 
    v3_lnx_printk("checking for IOMMU\n");
    iommu_avail = iommu_present(&pci_bus_type);
    
#endif
    
    v3_lnx_printk("IOMMU status =%d\n", iommu_avail);
    
    if (iommu_avail == true) {
	v3_lnx_printk("Setting host PCI device (%s) as IOMMU\n", host_dev->name);
	host_dev->v3_dev.iface = IOMMU;
    } else {
	v3_lnx_printk("Error: Cannot passthrough PCI device without IOMMU\n");
	return -1;
    }

    return 0;
}



static int 
remove_pci_hw_dev(unsigned int  cmd,
		  unsigned long arg)
{   
    void __user            * argp     = (void __user *)arg;
    struct host_pci_device * host_dev = NULL;
    struct v3_hw_pci_dev     hw_dev_arg;

    unsigned long flags;
    int ret = 0;

    if (copy_from_user(&hw_dev_arg, argp, sizeof(struct v3_hw_pci_dev))) {
	ERROR("copy from user error...\n");
	return -EFAULT;
    }


    spin_lock_irqsave(&lock, flags);
    {
	host_dev = find_dev_by_name(hw_dev_arg.name);
	
	if (host_dev == NULL) {
	    ERROR("Could not find PCI Deivice (%s)\n", hw_dev_arg.name);
	    ret = -1;
	} else if (host_dev->in_use == 1) {
	    ERROR("PCI Device (%s) is still in use\n", hw_dev_arg.name);
	    ret = -1;
	} else {
	    list_del(&(host_dev->dev_node));
	}
    }
    spin_unlock_irqrestore(&lock, flags);
    

    if (ret == -1) {
	return -1;
    }

    palacios_kfree(host_dev);

    return 0;
}




static int 
host_pci_init( void ) 
{
    INIT_LIST_HEAD(&(device_list));
    spin_lock_init(&lock);

    V3_Init_Host_PCI(&pci_hooks);

    add_global_ctrl(V3_ADD_PCI,    register_pci_hw_dev);
    add_global_ctrl(V3_REMOVE_PCI, remove_pci_hw_dev);

    return 0;
}


static int 
host_pci_deinit( void ) 
{
    struct host_pci_device * host_dev = NULL;
    struct host_pci_device * tmp_dev  = NULL;
    unsigned long flags;

    spin_lock_irqsave(&lock, flags);
    {

	list_for_each_entry_safe(host_dev, tmp_dev, &device_list, dev_node) {
	    list_del(&(host_dev->dev_node));
	    palacios_kfree(host_dev);
	    
	}
    }
    spin_unlock_irqrestore(&lock, flags);

    return 0;
}


static struct linux_ext host_pci_ext = {
    .name   = "HOST_PCI",
    .init   = host_pci_init,
    .deinit = host_pci_deinit,
};



register_extension(&host_pci_ext);
