/** 
 * PCI device interface code for passthrough PCI device
 * This provides an interface to the Kitten PCI code to:
 *   -  detect BARs
 *   -  update config space parameters 
 * 
 * (c) 2013, Jack Lange <jacklange@cs.pitt.edu>
 */

#include <lwk/spinlock.h>
#include <lwk/string.h>
#include <arch/uaccess.h>

#include "palacios.h"
#include "kitten-exts.h"


#include <interfaces/host_pci.h>


#define PCI_HDR_SIZE 256
#define PCI_DEVFN(slot, func) ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEV_NUM(devfn) (((devfn) >> 3) & 0x1f)
#define PCI_FUNC_NUM(devfn) ((devfn) & 0x07))


struct host_pci_device {
    char name[128];

    enum {PASSTHROUGH, USER} type; 

    enum {INTX_IRQ, MSI_IRQ, MSIX_IRQ} irq_type;
    uint32_t num_vecs;

    union {
        struct {
            u8 in_use;
            u8 iommu_enabled;

            u32 bus;
            u32 devfn;

            spinlock_t intx_lock;
            u8 intx_disabled;

            u32 num_msix_vecs;
            struct msix_entry * msix_entries;
            //struct iommu_domain * iommu_domain;

            //struct pci_dev * dev;
        } hw_dev;
    };

    struct v3_host_pci_dev v3_dev;

    struct list_head dev_node;
};


static struct list_head device_list;
static spinlock_t lock;

static struct host_pci_device * find_dev_by_name(char * name) {
    struct host_pci_device * dev = NULL;

    list_for_each_entry(dev, &device_list, dev_node) {
        if (strncmp(dev->name, name, 128) == 0) {
            return dev;
        }
    }

    return NULL;
}



static int 
host_pci_config_write(struct v3_host_pci_dev * v3_dev, u32 reg_num,
		      void * src, u32 length) {
    return 0;
}

static int
host_pci_config_read(struct v3_host_pci_dev * v3_dev, u32 reg_num,
		     void * dst, u32 length) {
    return 0;
}

static int
host_pci_ack_irq(struct v3_host_pci_dev * v3_dev, unsigned int vector) {
    return 0;
}

static int 
host_pci_cmd(struct v3_host_pci_dev * v3_dev, host_pci_cmd_t cmd, u64 arg) {
    return 0;
}



static struct v3_host_pci_dev * 
host_pci_request_dev(char * url, void * v3_ctx) {
    
    return NULL;
}


static struct v3_host_pci_hooks host_pci_hooks = {
    .request_device = host_pci_request_dev,
    .config_write = host_pci_config_write,
    .config_read = host_pci_config_read,
    .ack_irq = host_pci_ack_irq,
    .pci_cmd = host_pci_cmd,
};


static int host_pci_setup_dev(struct host_pci_device * dev) {

    // decode and cache BAR registers
    // -- Already setup on the Linux side

    // Cache Expansion ROM

    // cache configuration space

    // reserve device IRQ vector for IPI



    return 0;
}


static int register_pci_hw_dev(unsigned int cmd, unsigned long arg) {
    void __user * argp = (void __user *)arg;
    struct v3_hw_pci_dev pci_dev_arg;
    struct host_pci_device * host_dev = NULL;
    unsigned long flags;
    int ret = 0;

    if (copy_from_user(&pci_dev_arg, argp, sizeof(struct v3_hw_pci_dev))) {
        printk("%s(%d): copy from user error...\n", __FILE__, __LINE__);
        return -EFAULT;
    }

    host_dev = kmem_alloc(sizeof(struct host_pci_device));
    memset(host_dev, 0, sizeof(struct host_pci_device));

    printk("registering host device %s\n", pci_dev_arg.name);
    printk("Bus=%d, device=%d, function=%d\n", 
	   pci_dev_arg.bus, pci_dev_arg.dev, pci_dev_arg.func);

    strncpy(host_dev->name, pci_dev_arg.name, 128);
    host_dev->v3_dev.host_data = host_dev;


    host_dev->type = PASSTHROUGH;
    host_dev->hw_dev.bus = pci_dev_arg.bus;
    host_dev->hw_dev.devfn = PCI_DEVFN(pci_dev_arg.dev, pci_dev_arg.func);


    if (!find_dev_by_name(pci_dev_arg.name)) {
        spin_lock_irqsave(&lock, flags);
        list_add(&(host_dev->dev_node), &device_list);
        spin_unlock_irqrestore(&lock, flags);
    } else {
        // Error device already exists
	printk(KERN_ERR "Error: Device %s is already registered\n", pci_dev_arg.name);
        kmem_free(host_dev);
        return -EFAULT;
    }

    {
        host_dev->hw_dev.intx_disabled = 1;
        spin_lock_init(&(host_dev->hw_dev.intx_lock));

        ret = host_pci_setup_dev(host_dev);
	
	if (ret == -1) {
	    printk(KERN_ERR "Could not setup pci device\n");
	    return -1;
	}
    }

    printk("Device %s registered\n", pci_dev_arg.name);

    return 0;
}



static int host_pci_init( void ) {
    INIT_LIST_HEAD(&device_list);
    spin_lock_init(&lock);

    V3_Init_Host_PCI(&host_pci_hooks);

    add_global_ctrl(V3_ADD_PCI_HW_DEV, register_pci_hw_dev);

    return 0;
}



static struct kitten_ext host_pci_ext = {
    .name = "HOST_PCI",
    .init = host_pci_init,
    .deinit = NULL,
    .guest_init = NULL,
    .guest_deinit = NULL
};


register_extension(&host_pci_ext);
