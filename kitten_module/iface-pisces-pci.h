/* Pisces PCI Passthorugh interface
 *  (c) Jiannan Ouyang, 2013
 *  ouyang@cs.pitt.edu 
 */

#ifndef _IFACE_PISCES_PCI_H_
#define _IFACE_PISCES_PCI_H_

#include <interfaces/host_pci.h>
#include <arch/pisces/pisces_lcall.h>
#include <arch/pisces/pisces_cmds.h>

struct pisces_pci_device {
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


struct pisces_pci_setup_cmd {
    union {
        struct pisces_cmd cmd;
        struct pisces_resp resp;
    } __attribute__((packed));
    char name[128];
    u32 domain;
    u32 bus;
    u32 devfn;
    u64 iommu_present;
    struct v3_host_pci_bar bars[6];
    struct v3_host_pci_bar exp_rom;
    uint8_t cfg_space[256];
};

#endif
