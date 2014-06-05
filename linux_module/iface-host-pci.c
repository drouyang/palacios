/* Host PCI interface 
 *  (c) Jack Lange, 2012
 *  jacklange@cs.pitt.edu 
 */

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "palacios.h"
#include "linux-exts.h"
#include "mm.h"

#include <interfaces/host_pci.h>

static struct list_head device_list;
static spinlock_t lock;




struct pci_dev;
struct iommu_domain;

struct host_pci_device {
    char name[128];
    
    enum {PASSTHROUGH, USER} type; 
  
    u8 in_use;

    union {
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

    };

    struct v3_host_pci_dev v3_dev;
    void * v3_ctx;



    struct list_head dev_node;
};


#include "iface-host-pci-hw.h"


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



static struct v3_host_pci_dev * 
request_pci_dev(char * url, 
		void * v3_ctx) 
{   
    struct host_pci_device * host_dev = NULL;
    unsigned long flags;

    spin_lock_irqsave(&lock, flags);
    {
	host_dev = find_dev_by_name(url);
    }
    spin_unlock_irqrestore(&lock, flags);
    
    if (host_dev == NULL) {
	ERROR("Could not find host device (%s)\n", url);
	return NULL;
    }

    if (host_dev->type == PASSTHROUGH) {
	if (reserve_hw_pci_dev(host_dev, v3_ctx) == -1) {
	    ERROR("Could not reserve host device (%s)\n", url);
	    return NULL;
	}
    } else {
	ERROR("Unsupported Host device type\n");
	return NULL;
    }

    host_dev->v3_ctx = v3_ctx;

    return &(host_dev->v3_dev);
}


static int 
release_pci_dev(struct v3_host_pci_dev * v3_dev) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
	release_hw_pci_dev(host_dev);
    }

    host_dev->v3_ctx = NULL;

    return 0;
}


static int
host_pci_config_write(struct v3_host_pci_dev * v3_dev, 
		      unsigned int             reg_num, 
		      void                   * src, 
		      unsigned int             length)
{
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
	return write_hw_pci_config(host_dev, reg_num, src, length);
    }
 
    ERROR("Error in config write handler\n");
    return -1;
}

static int 
host_pci_config_read(struct v3_host_pci_dev * v3_dev,
		     unsigned int             reg_num, 
		     void                   * dst, 
		     unsigned int             length)
{
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
	return read_hw_pci_config(host_dev, reg_num, dst, length);
    }
 
    ERROR("Error in config read handler\n");
    return -1;
}


static int
host_pci_ack_irq(struct v3_host_pci_dev * v3_dev, 
		 unsigned int             vector) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
	return hw_ack_irq(host_dev, vector);
    }
 
    ERROR("Error in config irq ack handler\n");
    return -1;
}



static int 
host_pci_cmd(struct v3_host_pci_dev * v3_dev, 
	     host_pci_cmd_t           cmd,
	     u64                      arg) 
{
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
	return hw_pci_cmd(host_dev, cmd, arg);
    }
 
    ERROR("Error in config pci cmd handler\n");
    return -1;
    
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
    int ret = 0;

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
    host_dev->type             = PASSTHROUGH;
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

    
    init_hw_pci_dev(host_dev);

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
