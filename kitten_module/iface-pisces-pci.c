/* Pisces PCI Passthorugh interface
 *  (c) Jiannan Ouyang, 2013
 *  ouyang@cs.pitt.edu 
 */

#include <lwk/types.h>
#include <lwk/kernel.h>
#include <lwk/string.h>
#include <lwk/spinlock.h>
#include <lwk/print.h>

#include <arch/uaccess.h>

#include "palacios.h"
#include "kitten-exts.h"
#include "iface-pisces-pci.h"

#define PCI_HDR_SIZE 256
#define PCI_DEVFN(slot, func) ((((slot) & 0x1f) << 3) | ((func) & 0x07))

static struct list_head device_list;
static spinlock_t lock;

static struct pisces_pci_device * find_dev_by_name(char * name) {
    struct pisces_pci_device * dev = NULL;

    list_for_each_entry(dev, &device_list, dev_node) {
        if (strncmp(dev->name, name, 128) == 0) {
            return dev;
        }
    }

    return NULL;
}


static struct v3_host_pci_dev * pisces_pci_request_dev(char * url, void * v3_ctx) {

    unsigned long flags;
    struct pisces_pci_device * host_dev = NULL;

    spin_lock_irqsave(&lock, flags);
    host_dev = find_dev_by_name(url);
    spin_unlock_irqrestore(&lock, flags);

    if (host_dev == NULL) {
        printk("Could not find host device (%s)\n", url);
        return NULL;
    }

    if (host_dev->type != PASSTHROUGH) {
        printk("Unsupported Host device type\n");
        return NULL;
    }

    /*
     * setup iommu
     */

    return &(host_dev->v3_dev);
}


static int pisces_pci_config_write(struct v3_host_pci_dev * v3_dev, unsigned int reg_num, 
        void * src, unsigned int length) {
    struct pisces_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
        printk("Error in config write handler\n");
        return -1;
    }

    return 0;

}

static int pisces_pci_config_read(struct v3_host_pci_dev * v3_dev, unsigned int reg_num, 
        void * dst, unsigned int length) {
    struct pisces_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type != PASSTHROUGH) {
        printk("Error in config read handler\n");
        return -1;
    }

    return 0;
}


static int pisces_pci_ack_irq(struct v3_host_pci_dev * v3_dev, unsigned int vector) {
    struct pisces_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type != PASSTHROUGH) {
        printk("Error in config irq ack handler\n");
        return -1;
    }

    return 0;
}


static int pisces_pci_cmd(struct v3_host_pci_dev * v3_dev, host_pci_cmd_t cmd, u64 arg) {
    struct pisces_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type != PASSTHROUGH) {
        printk("Error in config pci cmd handler\n");
        return -1;
    }

    return 0;
}

/* request Linux to
 * - pci_enable_device(dev)
 * - pci_request_regions(dev)
 * - pci_reset_function(dev);
 * - pci_save_state(dev);
 * - cache first 6 BAR regs into v3_dev->bars[]
 * - cache expansion rom bar into v3_dev->exp_rom
 * - cache configuration space into v3_dev->cfg_space[]
 * - check IOMMU to set v3_dev->iface to IOMMU;
 */
static int pisces_pci_setup_device(struct v3_host_pci_dev * v3_dev) {
    struct pisces_pci_setup_cmd setup_cmd;
    struct pisces_pci_setup_cmd * setup_resp = NULL;
    u64 ret = 0;

    struct pisces_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type != PASSTHROUGH) {
        printk("Error in config pci cmd handler\n");
        return -1;
    }

    setup_cmd.cmd.cmd = PISCES_LCALL_PCI_SETUP;
    setup_cmd.cmd.data_len = sizeof(struct pisces_pci_setup_cmd)
        - sizeof(struct pisces_cmd);

    pisces_exec_lcall((struct pisces_cmd *)&setup_cmd, (struct pisces_resp **)&setup_resp);

    ret = setup_resp->resp.status;
    if (ret < 0) {
        printk("pisces_pci_setup_device lcall failed\n");
        goto out;
    }

    if (setup_resp->iommu_present != 1) {
        printk("pisces_pci_setup_device iommu not present\n");
        goto out;
    }

    v3_dev->iface = IOMMU;
    memcpy(v3_dev->bars, setup_resp->bars,
            sizeof(struct v3_host_pci_dev) * 6);
    memcpy(&v3_dev->exp_rom, &setup_resp->exp_rom, 
            sizeof(struct v3_host_pci_dev));
    memcpy(v3_dev->cfg_space, setup_resp->cfg_space, 256);

out:
    kmem_free(setup_resp);
    return ret;
}


static struct v3_host_pci_hooks pisces_pci_hooks = {
    .request_device = pisces_pci_request_dev,
    .config_write = pisces_pci_config_write,
    .config_read = pisces_pci_config_read,
    .ack_irq = pisces_pci_ack_irq,
    .pci_cmd = pisces_pci_cmd,
};


static int register_pci_hw_dev(unsigned int cmd, unsigned long arg) {
    void __user * argp = (void __user *)arg;
    struct v3_hw_pci_dev hw_dev_arg ;
    struct pisces_pci_device * host_dev = NULL;
    unsigned long flags;
    int ret = 0;

    if (copy_from_user(&hw_dev_arg, argp, sizeof(struct v3_hw_pci_dev))) {
        printk("%s(%d): copy from user error...\n", __FILE__, __LINE__);
        return -EFAULT;
    }

    host_dev = kmem_alloc(sizeof(struct pisces_pci_device));
    memset(host_dev, 0, sizeof(struct pisces_pci_device));


    strncpy(host_dev->name, hw_dev_arg.name, 128);
    host_dev->v3_dev.host_data = host_dev;


    host_dev->type = PASSTHROUGH;
    host_dev->hw_dev.bus = hw_dev_arg.bus;
    host_dev->hw_dev.devfn = PCI_DEVFN(hw_dev_arg.dev, hw_dev_arg.func);


    spin_lock_irqsave(&lock, flags);
    if (!find_dev_by_name(hw_dev_arg.name)) {
        list_add(&(host_dev->dev_node), &device_list);
        ret = 1;
    }
    spin_unlock_irqrestore(&lock, flags);

    if (ret == 0) {
        // Error device already exists
        kmem_free(host_dev);
        return -EFAULT;
    }


    {
        int ret = 0;
        struct pci_dev * dev = NULL;
        struct v3_host_pci_dev * v3_dev = &(host_dev->v3_dev);

        host_dev->hw_dev.intx_disabled = 1;
        spin_lock_init(&(host_dev->hw_dev.intx_lock));

        pisces_pci_setup_device(v3_dev);
    }

    return 0;
}


static int pisces_pci_init( void ) {
    INIT_LIST_HEAD(&(device_list));
    spin_lock_init(&lock);

    V3_Init_Host_PCI(&pisces_pci_hooks);

    add_global_ctrl(V3_ADD_PCI_HW_DEV, register_pci_hw_dev);

    return 0;
}



static struct kitten_ext pisces_pci_ext = {
    .name = "PISCES_PCI",
    .init = pisces_pci_init,
};


register_extension(&pisces_pci_ext);
