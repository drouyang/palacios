/** 
 * PCI device interface code for passthrough PCI device
 * This provides an interface to the Kitten PCI code to:
 *   -  detect BARs
 *   -  update config space parameters 
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
#include <arch/uaccess.h>
#include <arch/proto.h>
#include <arch/pisces/pisces_lcall.h>
#include <arch/pisces/pisces_pci.h>

#include "palacios.h"
#include "kitten-exts.h"


#include <interfaces/host_pci.h>



#define PCI_HDR_SIZE 256
#define PCI_DEVFN(slot, func) ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEV_NUM(devfn) (((devfn) >> 3) & 0x1f)
#define PCI_FUNC_NUM(devfn) ((devfn) & 0x07)


/* TODO: vector management and ipi redirection table */

/* [64,238] in Kitten is free for use by devices
 * we grab [200, 219] for Pisces
 */
#define PISCES_PCI_VECTOR_START  200
#define PISCES_PCI_VECTOR_NUM    20


struct host_pci_device {
    char name[128];

    enum {PASSTHROUGH, USER} type; 

    enum {INTX_IRQ, MSI_IRQ, MSIX_IRQ} irq_type;
    uint32_t num_vecs;
    uint32_t intx_ipi_vector;
    uint32_t msi_irq_vector;

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
            pci_dev_t * dev;
        } hw_dev;
    };

    struct v3_host_pci_dev v3_dev;

    struct list_head dev_node;
};


struct pisces_pci_ack_irq_lcall {
    union {
        struct pisces_lcall lcall;
        struct pisces_lcall_resp lcall_resp;
    } __attribute__((packed));
    char name[128];
    u32 vector;
} __attribute__((packed));

struct pisces_pci_cmd_lcall {
    union {
        struct pisces_lcall lcall;
        struct pisces_lcall_resp lcall_resp;
    } __attribute__((packed));
    char name[128];
    host_pci_cmd_t cmd;
    u64 arg;
} __attribute__((packed));

struct pisces_pci_iommu_map_lcall {
    union {
        struct pisces_lcall lcall;
        struct pisces_lcall_resp lcall_resp;
    } __attribute__((packed));
    char name[128];
    u64 region_start;
    u64 region_end;
    u64 gpa;
    u32 last;
} __attribute__((packed));

u32 irq_vector_offset = 0;
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
write_hw_pci_config(struct host_pci_device * host_dev, u32 reg, void * data, u32 length) {
    pci_dev_t * dev = host_dev->hw_dev.dev;

    if (reg < 64) {
        return 0;
    }

    switch (length) {
        case 1:
            pci_write(dev, reg, 1, *(u8 *)data);
            break;
        case 2:
            pci_write(dev, reg, 2, *(u16 *)data);
            break;
        case 4:
            pci_write(dev, reg, 4, *(u32 *)data);
            break;
        default:
            printk(KERN_ERR "Invalid length of host PCI config update\n");
            return -1;
    }

    return 0;
}

static int
read_hw_pci_config(struct host_pci_device * host_dev, u32 reg, void * data, u32 length) {
    pci_dev_t * dev = host_dev->hw_dev.dev;

    switch(length) {
        case 1:
            *(u8 *)data = pci_read(dev, reg, 1);
            break;
        case 2:
            *(u16 *)data = pci_read(dev, reg, 2);
            break;
        case 4:
            *(u32 *)data = pci_read(dev, reg, 4);
            break;
        default:
            printk(KERN_ERR "Invalid length of host PCI config read\n");
            return -1;
    }

    return 0;
}


static int 
host_pci_config_write(struct v3_host_pci_dev * v3_dev, u32 reg_num,
              void * src, u32 length) {
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
        return write_hw_pci_config(host_dev, reg_num, src, length);
    }

    printk("Error in config write handler\n");
    return -1;
}

static int
host_pci_config_read(struct v3_host_pci_dev * v3_dev, u32 reg_num,
             void * dst, u32 length) {
    struct host_pci_device * host_dev = v3_dev->host_data;

    if (host_dev->type == PASSTHROUGH) {
        return read_hw_pci_config(host_dev, reg_num, dst, length);
    }

    printk("Error in config read handler\n");
    return -1;
}

static int
host_pci_ack_irq(struct v3_host_pci_dev * v3_dev, unsigned int vector) {
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pisces_pci_ack_irq_lcall ack_irq_lcall;
    struct pisces_pci_ack_irq_lcall * ack_irq_lcall_resp = NULL;
    int status = 0;

    ack_irq_lcall.lcall.lcall = PISCES_LCALL_PCI_ACK_IRQ;
    ack_irq_lcall.lcall.data_len = sizeof(struct pisces_pci_ack_irq_lcall) -
            sizeof(struct pisces_lcall);

    strncpy(ack_irq_lcall.name, host_dev->name, 128);
    ack_irq_lcall.vector = vector;
    
    status = pisces_lcall_exec((struct pisces_lcall *)&ack_irq_lcall, 
            (struct pisces_lcall_resp **)&ack_irq_lcall_resp);

    if (status != 0) {
        return -1;
    }

    status = ack_irq_lcall_resp->lcall_resp.status;
    kmem_free(ack_irq_lcall_resp);
    return status;
}

static void
msi_irq_handler(struct pt_regs * regs, unsigned int vector)
{
    struct host_pci_device * host_dev = NULL;

    list_for_each_entry(host_dev, &device_list, dev_node) {
        if (vector == host_dev->msi_irq_vector) {
            V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);
            break;
        }
    }
}

static void
msix_irq_handler(struct pt_regs * regs, unsigned int vector)
{
    struct host_pci_device * host_dev = NULL;
    int i;
    int matched = 0;

    //printk("MSI-X IRQ Handler (%d)\n", vector);

    list_for_each_entry(host_dev, &device_list, dev_node) {
        for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
            if (vector == host_dev->hw_dev.msix_entries[i].vector) {

                V3_host_pci_raise_irq(&(host_dev->v3_dev), i);
                matched = 1;
            }
        }
        if (!matched) {
	    printk("Error: could not find matching MSI-X entry for vector %d\n", vector);
        }
    }
}


static int 
host_pci_cmd(struct v3_host_pci_dev * v3_dev, host_pci_cmd_t cmd, u64 arg) {
    struct host_pci_device * host_dev = v3_dev->host_data;
    struct pisces_pci_cmd_lcall cmd_lcall;
    struct pisces_pci_cmd_lcall * cmd_lcall_resp = NULL;
    int status = 0;

    switch (cmd) {
        case HOST_PCI_CMD_MSI_ENABLE:
            {
                //u64 num_vecs = arg; /* number of vectors requested */

                /* TODO: support multiple vectors
                 * warning if number of vectors requested is greater
                 * than the number supported by hardware
                 */

                /* allocate MSI vector*/
                if (host_dev->msi_irq_vector == 0) {
                    unsigned long flags;

                    spin_lock_irqsave(&(lock), flags);
                    host_dev->msi_irq_vector = 
                        PISCES_PCI_VECTOR_START + irq_vector_offset;
                    irq_vector_offset++;
                    spin_unlock_irqrestore(&(lock), flags);

                    set_idtvec_handler(host_dev->msi_irq_vector, msi_irq_handler); 
                }


                status = pisces_pci_msi_enable(host_dev->hw_dev.dev, 
                        host_dev->msi_irq_vector);
                if (status) {
                    printk("Error enabling MSI\n");
                    break;
                }

                /* only support 1 vector for now */
                //host_dev->num_vecs = 1;
                break;
            }

        case HOST_PCI_CMD_MSI_DISABLE:
            /* free allocated vector number */

            status = pisces_pci_msi_disable(host_dev->hw_dev.dev);
            if (status) {
                printk("Error disabling MSI\n");
                break;
            }

            break;

        case HOST_PCI_CMD_MSIX_ENABLE:
            {
                int i;

                printk("Enabling MSI-X\n");

                host_dev->hw_dev.num_msix_vecs = arg;
                host_dev->hw_dev.msix_entries = kmem_alloc(
                        host_dev->hw_dev.num_msix_vecs * sizeof(struct msix_entry));

                if (host_dev->hw_dev.msix_entries == NULL) {
                    printk("Error allocating MSI-X entries\n");
                    break;
                }

                /* allocate MSI-X vectors */
                for (i = 0; i < host_dev->hw_dev.num_msix_vecs; i++) {
                    unsigned long flags;

                    host_dev->hw_dev.msix_entries[i].entry = i;
                    spin_lock_irqsave(&(lock), flags);
                    host_dev->hw_dev.msix_entries[i].vector 
                        = PISCES_PCI_VECTOR_START + irq_vector_offset;
                    irq_vector_offset++;
                    spin_unlock_irqrestore(&(lock), flags);

                    set_idtvec_handler(host_dev->hw_dev.msix_entries[i].vector,
                            msix_irq_handler); 
                }

                status = pisces_pci_msix_enable(
                        host_dev->hw_dev.dev, 
                        host_dev->hw_dev.msix_entries, 
                        host_dev->hw_dev.num_msix_vecs);
                if (status) {
                    printk("Error enabling MSI-X\n");
                    break;
                }

                break;
            }

        case HOST_PCI_CMD_MSIX_DISABLE:
            {
                /* free allocated vectors */

                printk("Disabling MSI-X\n");

                host_dev->hw_dev.num_msix_vecs = 0;
                kmem_free(host_dev->hw_dev.msix_entries);

                status = pisces_pci_msix_disable(host_dev->hw_dev.dev);
                if (status) {
                    printk("Error disabling MSI-X\n");
                    break;
                }

                break;
            }

        default:
            cmd_lcall.lcall.lcall = PISCES_LCALL_PCI_CMD;
            cmd_lcall.lcall.data_len = sizeof(struct pisces_pci_cmd_lcall) -
                sizeof(struct pisces_lcall);

            strncpy(cmd_lcall.name, host_dev->name, 128);
            cmd_lcall.cmd = cmd;
            cmd_lcall.arg = arg;

            /* forward pci cmd to Linux */
            status = pisces_lcall_exec((struct pisces_lcall *)&cmd_lcall,
                    (struct pisces_lcall_resp **)&cmd_lcall_resp);
            if (status < 0) {
                break;
            }

            status = cmd_lcall_resp->lcall_resp.status;
            kmem_free(cmd_lcall_resp);
    }

    return status;
}

static int
host_pci_iommu_map(struct host_pci_device * host_dev, u64 region_start,
        u64 region_end, u64 gpa, int last)
{
    struct pisces_pci_iommu_map_lcall iommu_lcall;
    struct pisces_pci_iommu_map_lcall * iommu_lcall_resp = NULL;
    int status = 0;

    iommu_lcall.lcall.lcall = PISCES_LCALL_PCI_IOMMU_MAP;
    iommu_lcall.lcall.data_len = sizeof(struct pisces_pci_iommu_map_lcall) -
            sizeof(struct pisces_lcall);

    strncpy(iommu_lcall.name, host_dev->name, 128);
    iommu_lcall.region_start = region_start;
    iommu_lcall.region_end = region_end;
    iommu_lcall.gpa = gpa;
    iommu_lcall.last = last;

    status = pisces_lcall_exec((struct pisces_lcall *)&iommu_lcall,
            (struct pisces_lcall_resp **)&iommu_lcall_resp);

    if (status != 0) {
        return -1;
    }

    status = iommu_lcall_resp->lcall_resp.status;
    kmem_free(iommu_lcall_resp);
    return status;
}

static int
reserve_hw_pci_dev(struct host_pci_device * host_dev, void * v3_ctx) {
    int ret = 0;
    unsigned long flags;
    struct v3_guest_mem_region region;
    u64 gpa = 0;

    spin_lock_irqsave(&lock, flags);
    if (host_dev->hw_dev.in_use == 0) {
        host_dev->hw_dev.in_use = 1;
    } else {
        ret = -1;
    }
    spin_unlock_irqrestore(&lock, flags);

    if (ret == -1)
        return ret;

    while (V3_get_guest_mem_region(v3_ctx, &region, gpa)) {
        printk("Memory region (GPA:%p), start=%p, end=%p\n",
            (void *)gpa,
            (void *)region.start,
            (void *)region.end
        );

        if (host_pci_iommu_map(host_dev, region.start, region.end, gpa, 0) != 0) {
            return -1;
        }

        gpa += (region.end - region.start);
    }

    if (host_pci_iommu_map(host_dev, 0, 0, 0, 1) != 0) {
        return -1;
    }

    return ret;
}

static struct v3_host_pci_dev * 
host_pci_request_dev(char * url, void * v3_ctx) {
    unsigned long flags;
    struct host_pci_device * host_dev = NULL;

    spin_lock_irqsave(&lock, flags);
    host_dev = find_dev_by_name(url);
    spin_unlock_irqrestore(&lock, flags);

    if (host_dev == NULL) {
        printk(KERN_ERR "Could not find host device (%s)\n", url);
        return NULL;
    }

    if (host_dev->type != PASSTHROUGH) {
        printk(KERN_ERR "Unsupported host device type\n");
        return NULL;
    }

    if (reserve_hw_pci_dev(host_dev, v3_ctx) == -1) {
        printk(KERN_ERR "Could not reserve host device (%s)\n", url);
        return NULL;
    }

    return &(host_dev->v3_dev);
}


static struct v3_host_pci_hooks host_pci_hooks = {
    .request_device = host_pci_request_dev,
    .config_write = host_pci_config_write,
    .config_read = host_pci_config_read,
    .ack_irq = host_pci_ack_irq,
    .pci_cmd = host_pci_cmd,
};


static void
intx_ipi_handler(struct pt_regs * regs, unsigned int vector)
{
    struct host_pci_device * host_dev = NULL;

    printk("Received PCI INTx IPI (vector=%u)\n", vector);

    list_for_each_entry(host_dev, &device_list, dev_node) {
        if (vector == host_dev->intx_ipi_vector) {
            V3_host_pci_raise_irq(&(host_dev->v3_dev), 0);
            break;
        }
    }
}


static int host_pci_setup_dev(struct host_pci_device * host_dev) {
    pci_dev_t * dev = NULL;
    struct v3_host_pci_dev * v3_dev = &(host_dev->v3_dev);

    dev = pci_get_bus_and_slot(host_dev->hw_dev.bus,
            host_dev->hw_dev.devfn);

    if (dev == NULL) {
        printk("Could not find HW pci device (bus=%d, devfn=%d)\n",
                host_dev->hw_dev.bus, host_dev->hw_dev.devfn);
        return -1;
    }

    // record pointer in dev state
    host_dev->hw_dev.dev = dev;

    host_dev->hw_dev.intx_disabled = 1;
    spin_lock_init(&(host_dev->hw_dev.intx_lock));

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
                bar->type = PT_BAR_NONE;
            } else if (pci_bar.mem == PCIM_BAR_MEM_SPACE) {
                bar->size = pci_bar.size;
                bar->addr = pci_bar.address;
                bar->prefetchable = (pci_bar.prefetch != 0);
                bar->cacheable = bar->prefetchable;

                if (pci_bar.type == 2) {
                    bar->type = PT_BAR_MEM64_LO;

                    {
                        struct v3_host_pci_bar * hi_bar = &(v3_dev->bars[++i]);
                        hi_bar->type = PT_BAR_MEM64_HI;
                        hi_bar->size = pci_bar.size;
                        hi_bar->addr = pci_bar.address;
                        hi_bar->prefetchable = (pci_bar.prefetch != 0);
                        hi_bar->cacheable = hi_bar->prefetchable;
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



#if 0
    // Cache Expansion ROM
    {
        pci_bar_t rom_bar;
        pcicfg_bar_decode(&dev->cfg, 0, &rom_bar);

        v3_dev->exp_rom.size = rom_bar.size;
        v3_dev->exp_rom.addr = rom_bar.address;
        v3_dev->exp_rom.type = PT_EXP_ROM;
        v3_dev->exp_rom.exp_rom_enabled = IORESOURCE_ROM_ENABLE;
        
    }
#endif
    // cache configuration space
    { 
        int i = 0;
        for (i = 0; i < PCI_HDR_SIZE; i += 4) {
            *(u32 *)&v3_dev->cfg_space[i] = pci_read(dev, i, 4);
        }
    }

    
    // reserve device IRQ vector for IPI
    {
        unsigned long flags;
        spin_lock_irqsave(&(lock), flags);
        host_dev->intx_ipi_vector = PISCES_PCI_VECTOR_START + irq_vector_offset;
        irq_vector_offset++;
        spin_unlock_irqrestore(&(lock), flags);
    }

    set_idtvec_handler(host_dev->intx_ipi_vector, intx_ipi_handler); 

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

    ret = host_pci_setup_dev(host_dev);
    if (ret == -1) {
        printk(KERN_ERR "Could not setup pci device\n");
        return -1;
    }

    printk("Device %s registered\n", pci_dev_arg.name);

    /* We use the ioctl return value to signal the ipi vector to user space */
    return host_dev->intx_ipi_vector;
}



static int host_pci_init( void ) {
    INIT_LIST_HEAD(&device_list);
    spin_lock_init(&lock);
    irq_vector_offset = 0;

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
