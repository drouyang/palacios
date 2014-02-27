/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2009, Jack Lange <jarusl@cs.northwestern.edu>
 * Copyright (c) 2009, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */ 
 

/* The PIIX4 is basically a PIIX3 with extended Power management support exposed through ACPI. 
   The principal difference is that there is a PM subdevice exposed via function 3, slaved off of the main PIIX
 */


#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <palacios/vmm_intr.h>

#include <devices/pci.h>
#include <devices/southbridge.h>


#ifndef V3_CONFIG_DEBUG_PIIX4
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif



#define PIIX4_PM_BASE_PORT         0xb000

#define PIIX4_PM_PMSTS_PORT        0x0000
#define PIIX4_PM_PMEN_PORT         0x0002
#define PIIX4_PM_PMCNTRL_PORT      0x0004
#define PIIX4_PM_PMTMR_PORT        0x0008
#define PIIX4_PM_GPSTS_PORT        0x000c
#define PIIX4_PM_GPEN_PORT         0x000e
#define PIIX4_PM_PCNTRL_PORT       0x0010
#define PIIX4_PM_PLVL2_PORT        0x0014
#define PIIX4_PM_PLVL4_PORT        0x0015
#define PIIX4_PM_GLBSTS_PORT       0x0018
#define PIIX4_PM_DEVSTS_PORT       0x001c
#define PIIX4_PM_GLBEN_PORT        0x0020
#define PIIX4_PM_GLBCTL_PORT       0x0028
#define PIIX4_PM_DEVCTL_PORT       0x002c
#define PIIX4_PM_GPIREG1_PORT      0x0030
#define PIIX4_PM_GPIREG2_PORT      0x0031
#define PIIX4_PM_GPIREG3_PORT      0x0032
#define PIIX4_PM_GPOREG1_PORT      0x0034
#define PIIX4_PM_GPOREG2_PORT      0x0035
#define PIIX4_PM_GPOREG3_PORT      0x0036
#define PIIX4_PM_GPOREG4_PORT      0x0037

#define PIIX4_SMI_CMD_PORT	   0x00b2



struct pm_control_reg {
    union {
	uint16_t value;
	struct {
            uint16_t sci_en		   : 1; // sci enable
	    uint16_t brld_en_bm            : 1; // bus master reload enable
	    uint16_t glb_rls               : 1; // global release
	    uint16_t rsvd1		   : 7;
            uint16_t sus_typ               : 3; // suspend type
	    uint16_t sus_en		   : 1; // suspend enable
	    uint16_t rsvd2		   : 2; 
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct piix4_internal {

    struct v3_southbridge southbridge;

    struct pci_device * pm_subfunction;

    // PM IO PORT registers
    uint16_t pmsts;     // pm status reg (offset = 0x00, len = 2)
    uint16_t pmen;      // pm enable reg (offset = 0x02, len = 2)
    struct pm_control_reg pmcntrl;   // pm cntrl reg  (offset = 0x04, len = 2)
    uint32_t pmtmr;     // pm timer reg  (offset = 0x08, len = 3)
};


struct iort_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t times_16bit   : 2;
	    uint8_t enable_16bit  : 1;
	    uint8_t times_8bit    : 3;
	    uint8_t enable_8bit   : 1;
	    uint8_t dmaac         : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

struct xbcs_reg {
    union {
	uint16_t value;
	struct {
	    uint8_t rtc_addr_en        : 1;
	    uint8_t kb_ctrl_en         : 1;
	    uint8_t bioscs_wprot_en    : 1;
	    uint8_t rsvd1              : 1;
	    uint8_t irq12_mouse_fn_en  : 1;
	    uint8_t coproc_err_fn_en   : 1;
	    uint8_t lower_bios_en      : 1;
	    uint8_t ext_bios_en        : 1;
	    uint8_t apic_chip_sel      : 1;
	    uint8_t piix_rsvd          : 7;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct pirq_route_ctrl_req {
    union {
	uint8_t value;
	struct {
	    uint8_t irq_routing        : 4;
	    uint8_t rsvd               : 3;
	    uint8_t irq_route_en       : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

struct top_of_mem_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t rsvd1                    : 1;
    uint8_t isadma_reg_fwd_en        : 1;
	    uint8_t piix_rsvd                : 1;
	    uint8_t isadma_lo_bios_fwd_en    : 1;
	    uint8_t top_of_mem               : 4;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

// Miscellaneous Status register
struct misc_stat_reg {
    union {
	uint16_t value;
	struct {
	    uint8_t isa_clk_div              : 1;
	    uint8_t piix_rsvd1               : 1;
	    uint8_t pci_hdr_type_en          : 1;
	    uint8_t rsvd1                    : 1;
	    uint8_t usb_en                   : 1;
	    uint8_t rsvd2                    : 1;
	    uint8_t ext_sm_mode_en           : 1;
	    uint8_t nb_retry_en              : 1;
	    uint8_t rsvd3                    : 7;
	    uint8_t serr_gen_delayed_tranx   : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));



// Motherboard Device IRQ route control register
struct mb_irq_ctrl_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t irq_routing              : 4;
	    uint8_t rsvd                     : 1;
	    uint8_t irq0_en                  : 1;
	    uint8_t irq_sharing_en           : 1;
	    uint8_t irq_routing_en           : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

// Motherboard Device DMA control register
struct mb_dma_ctrl_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t type_f_dma_routing       : 3;
	    uint8_t piix_rsvd                : 1;
	    uint8_t rsvd                     : 3;
	    uint8_t type_f_dma_buf_en        : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


// Programmable Chip Select Control Register
struct prg_chip_sel_ctrl_reg {
    union {
	uint16_t value;
	struct {
	    uint8_t pcs_addr_mask            : 2;
	    uint16_t pcs_addr                : 14;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


// APIC base address relocation register
struct apic_base_addr_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t y_base_addr             : 2;
	    uint8_t x_base_addr             : 4;
	    uint8_t a12_mask                : 1;
	    uint8_t rsvd                    : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


// Deterministic Latency control register
struct deter_lat_ctrl_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t delayed_trans_en        : 1;
	    uint8_t pass_release_en         : 1;
	    uint8_t usb_pass_release_en     : 1;
	    uint8_t serr_gen_trans_tmout_en : 1;
	    uint8_t rsvd                    : 4;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

// SMI Control Register
struct smi_ctrl_reg {
    union {
	uint8_t value;
	struct {
	    uint8_t smi_gate               : 1;
	    uint8_t stpclk_sig_en          : 1;
	    uint8_t stpclk_scaling_en      : 1;
	    uint8_t fast_off_tmr_freeze    : 2;
	    uint8_t rsvd                   : 3;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));

// SMI Enable register
struct smi_enable_reg {
    union {
	uint16_t value;
	struct {
	    uint8_t irq1_smi_en            : 1; // (keyboard irq)
	    uint8_t irq3_smi_en            : 1; // (COM1/COM3/Mouse irq)
	    uint8_t irq4_smi_en            : 1; // (COM2/COM4/Mouse irq)
	    uint8_t irq8_smi_en            : 1; // (RTC irq)
	    uint8_t irq12_smi_en           : 1; // (PS/2 mouse irq)
	    uint8_t fast_off_tmr_en        : 1;
	    uint8_t ext_smi_en             : 1;
	    uint8_t apic_wr_smi_en         : 1;
	    uint8_t legacy_usb_smi_en      : 1;
	    uint8_t rsvd                   : 7;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


// System Event Enable register
struct sys_evt_en_reg {
    union {
	uint32_t value;
	struct {
	    uint8_t firq0_en               : 1;
	    uint8_t firq1_en               : 1;
	    uint8_t rsvd1                  : 1;
	    uint8_t firq3_en               : 1;
	    uint8_t firq4_en               : 1;
	    uint8_t firq5_en               : 1;
	    uint8_t firq6_en               : 1;
	    uint8_t firq7_en               : 1;
	    uint8_t firq8_en               : 1;
	    uint8_t firq9_en               : 1;
	    uint8_t firq10_en              : 1;
	    uint8_t firq11_en              : 1;
	    uint8_t firq12_en              : 1;
	    uint8_t firq13_en              : 1;
	    uint8_t firq14_en              : 1;
	    uint8_t firq15_en              : 1;
	    uint16_t rsvd2                 : 12;
	    uint8_t fast_off_apic_en       : 1;
	    uint8_t fast_off_nmi_en        : 1;
	    uint8_t intr_en                : 1;
	    uint8_t fast_off_smi_en        : 1;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


// SMI Request Register
struct smi_req_reg {
    union {
	uint16_t value;
	struct {
	    uint8_t irq1_req_smi_stat      : 1;
	    uint8_t irq3_req_smi_stat      : 1;
	    uint8_t irq4_req_smi_stat      : 1;
	    uint8_t irq8_req_smi_stat      : 1;
	    uint8_t irq12_req_smi_stat     : 1;
	    uint8_t fast_off_tmr_exp_stat  : 1;
	    uint8_t extsmi_stat            : 1;
	    uint8_t apm_smi_stat           : 1;
	    uint8_t legacy_usb_smi_stat    : 1;
	    uint8_t rsvd                   : 7;
	} __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed));


struct piix4_config_space {
    uint8_t rsvd1[12];            // 0x40 - 0x4b

    // ISA I/O Recovery timer register
    uint8_t iort;                 // 0x4c        (default 0x4d)
    uint8_t rsvd2;                // 0x4d

    // X-Bus Chip select register
    uint16_t xbcs;                // 0x4e - 0x4f (default: 0x03)
    uint8_t rsvd3[16];            // 0x50 - 0x5f

    // pirq route control register (IRQs A-D)
    uint8_t pirq_rc[4];           // 0x60 - 0x63 (default: 0x80) 
    uint8_t rsvd4[5];             // 0x64 - 0x68

    // top of memory register
    uint8_t top_of_mem;           // 0x69        (default: 0x02)

    // Miscellaneous status register
    uint16_t mstat;               // 0x6A - 0x6B (default: undefined)
    uint8_t rsvd5[4];             // 0x6c - 0x6f

    // Motherboard device IRQ route control register
    uint8_t mbirq0;                // 0x70        (default: 0x80)
    uint8_t rsvd6;                 // 0x71 (piix only)
    uint8_t rsvd7[4];              // 0x72 - 0x75

    // Motherboard Device DMA Control registers
    uint8_t mbdma0;                // 0x76        (default: 0x0c)
    uint8_t mbdma1;                // 0x77        (default: 0x0c)

    // Programmable Chip Select Control Register  
    uint16_t pcsc;                 // 0x78 - 0x79 (default: 0x0002)
    uint8_t rsvd8[6];              // 0x7A - 0x7F

    // APIC base address relocation register
    uint8_t apicbase;              // 0x80        (default: 0x00)
    uint8_t rsvd9;                 // 0x81


    // Deterministic Latency control register
    uint8_t dlc;                   // 0x82        (default: 0x00)
    uint8_t rsvd10[29];            // 0x83 - 0x9f


    // SMI Control Register
    uint8_t smicntl;               // 0xa0        (default: 0x08)
    uint8_t rsvd11;                // 0xa1

    // SMI Enable register
    uint16_t smien;                // 0xa2 - 0xa3 (default: 0x0000)

    // System Event Enable register
    uint32_t see;                  // 0xa4 - 0xa7 (default: 0x00000000)

    // Fast off timer register
    uint8_t ftmr;                  // 0xa8        (default: 0x0f)
    uint8_t rsvd12;                // 0xa9

    // SMI Request Register
    uint16_t smireq;               // 0xaa - 0xab (default: 0x0000)

    // Clock Scale stpclk low timer
    uint8_t ctltmr;                // 0xac        (default: 0x00)
    uint8_t rsvd13;                // 0xad

    // Slock Scale STPCLK high timer
    uint8_t cthtmr;                // 0xae        (default: 0x00)

} __attribute__((packed));

static int reset_piix4(struct piix4_internal * piix4) {
    struct v3_southbridge * southbridge = &(piix4->southbridge);
    struct pci_device * pci_dev = southbridge->southbridge_pci;
    struct piix4_config_space * piix4_cfg = (struct piix4_config_space *)(pci_dev->config_data);

    pci_dev->config_header.command = 0x0007; // master, memory and I/O
    pci_dev->config_header.status = 0x0200;

    piix4_cfg->iort = 0x4d;
    piix4_cfg->xbcs = 0x0003;
    piix4_cfg->pirq_rc[0] = 0x80;
    piix4_cfg->pirq_rc[1] = 0x80;
    piix4_cfg->pirq_rc[2] = 0x80;
    piix4_cfg->pirq_rc[3] = 0x80;
    piix4_cfg->top_of_mem = 0x02;
    piix4_cfg->mbirq0 = 0x80;
    piix4_cfg->mbdma0 = 0x0c;
    piix4_cfg->mbdma1 = 0x0c;
    piix4_cfg->pcsc = 0x0002;
    piix4_cfg->apicbase = 0x00;
    piix4_cfg->dlc = 0x00;
    piix4_cfg->smicntl = 0x08;
    piix4_cfg->smien = 0x0000;
    piix4_cfg->see = 0x00000000;
    piix4_cfg->ftmr = 0x0f;
    piix4_cfg->smireq = 0x0000;
    piix4_cfg->ctltmr = 0x00;
    piix4_cfg->cthtmr = 0x00;

    return 0;
}



struct piix4_pm_base {
    uint32_t    type    : 1; // read-only: val=1
    uint32_t    rsvd1   : 5; // read-only: val=0
    uint32_t    addr    : 10; // read-write: base port #
    uint32_t    rsvd2   : 16; // read-only: val=0
} __attribute__((packed));

struct piix4_pm_config_space {
    uint32_t io_port_base;         // 0x40 - 0x43, 64 IO ports

    uint32_t cnta;                 // 0x44 - 0x47
    uint32_t cntb;                 // 0x48 - 0x4b
    uint32_t gpictl;               // 0x4c - 0x4f

    uint32_t devres_d   : 24;      // 0x50 - 0x52
    uint8_t rsvd1;                 // 0x53

    uint32_t devact_a;             // 0x54 - 0x57
    uint32_t devact_b;             // 0x58 - 0x5b
    
    uint32_t devres_a;             // 0x5c - 0x5f
    uint32_t devres_b;             // 0x60 - 0x63
    uint32_t devres_c;             // 0x64 - 0x67
    uint32_t devres_e;             // 0x68 - 0x6a
    uint32_t devres_f;             // 0x6c - 0x6f
    uint32_t devres_g   : 24;      // 0x70 - 0x72
    uint8_t rsvd2;                 // 0x73
    uint32_t devres_h;             // 0x74 - 0x77
    uint32_t devres_i;             // 0x78 - 0x7b
    uint32_t devres_j;             // 0x7c - 0x7f

    uint8_t pm_reg_misc;           // 0x80
    uint8_t rsvd3[15];             // 0x81 - 0x8f

    uint32_t smb_base_addr;        // 0x90 - 0x93
    
    uint8_t rsvd4[62];             // 0x94 - 0xd1

    uint8_t smb_hst_cfg;           // 0xd2
    uint8_t smb_slv_cmd;           // 0xd3
    uint8_t smb_shdw_1;            // 0xd4
    uint8_t smb_shdw_2;            // 0xd5
    uint8_t smb_rev;               // 0xd6

} __attribute__((packed));




static int reset_piix4_pm(struct piix4_internal * piix4) {
    struct pci_device * pci_dev = piix4->pm_subfunction;
    struct piix4_pm_config_space * pm_cfg = (struct piix4_pm_config_space *)(pci_dev->config_data);

    pci_dev->config_header.command = 0x0007; // master, memory and I/O
    pci_dev->config_header.status = 0x0200;

    pm_cfg->io_port_base = 0xb001;
    pm_cfg->cnta = 0;
    pm_cfg->cntb = 0;
    pm_cfg->gpictl = 0;
    pm_cfg->devres_d = 0;
    pm_cfg->devact_a = 0;
    pm_cfg->devact_b = 0;
    pm_cfg->devres_a = 0;
    pm_cfg->devres_b = 0;
    pm_cfg->devres_c = 0;
    pm_cfg->devres_e = 0;
    pm_cfg->devres_f = 0;
    pm_cfg->devres_g = 0;
    pm_cfg->devres_h = 0;
    pm_cfg->devres_i = 0;
    pm_cfg->devres_j = 0;
    pm_cfg->pm_reg_misc = 0;
    pm_cfg->smb_base_addr = 1;
    pm_cfg->smb_hst_cfg = 0;
    pm_cfg->smb_slv_cmd = 0;
    pm_cfg->smb_shdw_1 = 0;
    pm_cfg->smb_shdw_2 = 0;
    pm_cfg->smb_rev = 0;

    return 0;
}


//irq is pirq_rc[intr_pin + pci_dev_num - 1] & 0xf
/*
struct pirq_rc_reg {
       uint8_t irq         : 4;
       uint8_t rsvd        : 3;
       uint8_t disabled    : 1; // (1=disabled, 0=enabled)
}
*/


static int raise_pci_irq(struct pci_device * pci_dev, void * dev_data, struct v3_irq * vec) {
    struct v3_southbridge * southbridge = dev_data;
    //    struct piix4_internal * piix4 = (struct piix4_internal *)container_of(southbridge, struct piix4_internal, southbridge);
    struct pci_device * piix4_pci = southbridge->southbridge_pci;
    struct piix4_config_space * piix4_cfg = (struct piix4_config_space *)(piix4_pci->config_data);
    int intr_pin = pci_dev->config_header.intr_pin - 1;
    int irq_index = (intr_pin + pci_dev->dev_num - 1) & 0x3;
    struct v3_irq irq; // Make a copy of the irq state because we will switch the irq number

    irq.ack = vec->ack;
    irq.private_data = vec->private_data;

    /*
    PrintError("Raising PCI dev %d intr %d via IOAPIC as IRQ %d and via PIRQ as IRQ %d on VM %p\n", 
	       pci_dev->dev_num, pci_dev->config_header.intr_pin, 
	       16+irq_index,
	       piix4_cfg->pirq_rc[irq_index], piix4->vm);
    */

    PrintDebug("PIIX4: Raising irq_idx=%d: intr_pin=%d,  PIRQ[0]=%d, PIRQ[1]=%d, PIRQ[2]=%d, PIRQ[3]=%d\n", 
	     irq_index, intr_pin,
	     piix4_cfg->pirq_rc[0],
	     piix4_cfg->pirq_rc[1],
	     piix4_cfg->pirq_rc[2],
	     piix4_cfg->pirq_rc[3]);



    // deliver first by PIRQ, if it exists
    //
    if (piix4_cfg->pirq_rc[irq_index] < 16) {
	irq.irq = piix4_cfg->pirq_rc[irq_index] & 0xf;

	//PrintDebug("Raising PIIX IRQ %d from %s\n", irq.irq, pci_dev->name);
	v3_raise_acked_irq(southbridge->vm, irq);
    } else {
      // not an error
    }

    // deliver next via the PCI0 to ioapic mapping defined in the 
    // mptable (ioapic, pins 16->19 are used for PCI0)
    // ideally this would check to verify that an ioapic is actually available
    irq.irq = (irq_index + 1) + 16;
    //  PrintDebug("Raising PIIX IRQ (#2) %d from %s\n", irq.irq, pci_dev->name);
    v3_raise_acked_irq(southbridge->vm, irq);
    

    return 0;
}



static int lower_pci_irq(struct pci_device * pci_dev, void * dev_data, struct v3_irq * vec) {
    struct v3_southbridge * southbridge = dev_data;
    //    struct piix4_internal * piix4 = (struct piix4_internal *)container_of(southbridge, struct piix4_internal, southbridge);
    struct pci_device * piix4_pci = southbridge->southbridge_pci;
    struct piix4_config_space * piix4_cfg = (struct piix4_config_space *)(piix4_pci->config_data);
    int intr_pin = pci_dev->config_header.intr_pin - 1;
    int irq_index = (intr_pin + pci_dev->dev_num - 1) & 0x3;
    struct v3_irq irq; // Make a copy of the irq state because we will switch the irq number

    irq.ack = vec->ack;
    irq.private_data = vec->private_data;

    //    PrintDebug("Lowering PCI IRQ %d\n", piix4_cfg->pirq_rc[irq_index]);

    // First, lower the pin on the ioapic
    irq.irq = (irq_index + 1) + 16;
    v3_lower_acked_irq(southbridge->vm, irq);
    
    // Next, lower whatever we asserted by the PIRQs
    if (piix4_cfg->pirq_rc[irq_index] < 16) {
	irq.irq = piix4_cfg->pirq_rc[irq_index] & 0xf;
	v3_lower_acked_irq(southbridge->vm, irq);
    } else {
      // not an error
    }

    return 0;
}



static int piix_free(struct v3_southbridge * piix4) {

    // unregister pci

    V3_Free(piix4);
    return 0;
}


static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))piix_free,
};



static int smi_read_port(struct guest_info * core, uint16_t port, 
			void * dst, uint32_t length, void * priv_data) {
    PrintError("PIIX4 SMI port read unsupported\n");
    return -1;
}


static int smi_write_port(struct guest_info * core, uint16_t port, 
			 void * src, uint32_t length, void * priv_data) {
    struct v3_southbridge * southbridge = priv_data;
    struct piix4_internal * piix4 = container_of(southbridge, struct piix4_internal, southbridge);

    uint8_t val = *((uint8_t *)src);

    if (length != 1) {
	PrintError("PIIX4 SMI port write: invalid length (%d)\n", length);
	return -1;
    }

    switch (port) {
        case 0xb2:
            if (val == 0xf1) {
                piix4->pmcntrl.sci_en = 1;
            } else if (val == 0xf0) {
                piix4->pmcntrl.sci_en = 0;
	    }

	    break;
        default: 
            PrintError("PIIX4 PM port read unsupported on port 0x%x (length = %d)\n", port, length);
            return -1;
    }

    return length;
}


static int pm_read_port(struct guest_info * core, uint16_t port, 
			void * dst, uint32_t length, void * priv_data) {
    struct v3_southbridge * southbridge = priv_data;
    struct piix4_internal * piix4 = container_of(southbridge, struct piix4_internal, southbridge);
    uint16_t port_offset = port - PIIX4_PM_BASE_PORT;
    

    switch (port_offset) {
	case PIIX4_PM_PMSTS_PORT:
	    // There is a disagreement between the spec and seabios about this port....

	    if (length != 2) {
		PrintError("Invalid read length (%d) for PIIX4 PMSTS port\n", length);
		return -1;
	    }
	    
	    *(uint16_t *)dst = piix4->pmsts;

	    break;
	case PIIX4_PM_PMEN_PORT:
	    // There is a disagreement between the spec and seabios about this port....

	    if (length != 2) {
		PrintError("Invalid read length (%d) for PIIX4 PMEN port\n", length);
		return -1;
	    }
	    
	    *(uint16_t *)dst = piix4->pmen;

	    break;
	case PIIX4_PM_PMCNTRL_PORT:
	    if (length != 2) {
		PrintError("Invalid read length (%d) for PIIX4 PMCNTRL port\n", length);
		return -1;
	    }
	    
	    *(uint16_t *)dst = piix4->pmcntrl.value;

	    break;
	case PIIX4_PM_PMTMR_PORT:
	    // There is a disagreement between the spec and seabios about this port....

	    if (length != 4) {
		PrintError("Invalid read length (%d) for PIIX4 PTMR port\n", length);
		return -1;
	    }
	    
	    *(uint32_t *)dst = piix4->pmtmr;

	    break;
	default:
	    PrintError("PIIX4 PM port read unsupported on port 0x%x (length = %d)\n", port, length);
	    return -1;
    }

    return length;
}

static int pm_write_port(struct guest_info * core, uint16_t port, 
			 void * src, uint32_t length, void * priv_data) {
    struct v3_southbridge * southbridge = priv_data;
    struct piix4_internal * piix4 = container_of(southbridge, struct piix4_internal, southbridge);
    uint16_t port_offset = port - PIIX4_PM_BASE_PORT;
    

    switch (port_offset) {
	case PIIX4_PM_PMSTS_PORT:
	    // There is a disagreement between the spec and seabios about this port....

	    if (length != 2) {
		PrintError("Invalid write length (%d) for PIIX4 PMSTS port\n", length);
		return -1;
	    }
	    
	    piix4->pmsts = *(uint16_t *)src;

	    break;
	case PIIX4_PM_PMEN_PORT:
	    if (length != 2) {
		PrintError("Invalid write length (%d) for PIIX4 PMEN port\n", length);
		return -1;
	    }
	    
	    piix4->pmen = *(uint16_t *)src;

	    break;
	case PIIX4_PM_PMCNTRL_PORT:
	    if (length != 2) {
		PrintError("Invalid write length (%d) for PIIX4 PMCNTRL port\n", length);
		return -1;
	    }
	    
	    piix4->pmcntrl.value = *(uint16_t *)src;

	    break;
	case PIIX4_PM_PMTMR_PORT:
	    // There is a disagreement between the spec and seabios about this port....

	    if (length != 4) {
		PrintError("Invalid write length (%d) for PIIX4 PTMR port\n", length);
		return -1;
	    }
	    
	    piix4->pmtmr = *(uint32_t *)src;

	    break;
	default:
	    PrintError("PIIX4 PM port write unsupported on port 0x%x (length = %d)\n", port, length);
	    return -1;
    }

    return length;

}

static int setup_pci(struct vm_device * dev) {
    struct v3_southbridge * southbridge = dev->private_data;
    struct piix4_internal * piix4 = container_of(southbridge, struct piix4_internal, southbridge);
    struct pci_device * pci_dev = NULL;
    struct pci_device * pm_dev = NULL;
    struct v3_pci_bar bars[6];
    int i;
    int ret = 0;
    int bus_num = 0;

    for (i = 0; i < 6; i++) {
	bars[i].type = PCI_BAR_NONE;
    }

    pci_dev = v3_pci_register_device(southbridge->pci_bus, PCI_MULTIFUNCTION, 
				     bus_num, -1, 0, 
				     "PIIX4", bars, 
				     NULL, NULL, NULL, NULL, southbridge);
    if (pci_dev == NULL) {
	PrintError("Could not register PCI Device for PIIX4\n");
	return -1;
    }

    pci_dev->config_header.vendor_id = 0x8086;
    pci_dev->config_header.device_id = 0x7110; 
    pci_dev->config_header.class = PCI_CLASS_BRIDGE;
    pci_dev->config_header.subclass = PCI_BRIDGE_SUBCLASS_PCI_ISA; 

    southbridge->southbridge_pci = pci_dev;

    v3_pci_set_irq_bridge(southbridge->pci_bus, bus_num, raise_pci_irq, lower_pci_irq, southbridge);

    reset_piix4(piix4);


    // Setup PM subfunction
    
    for (i = 0; i < 6; i++) {
	bars[i].type = PCI_BAR_NONE;
    }


    // TODO: We should hook the config space to determine if the IO ports get changed
    pm_dev = v3_pci_register_device(southbridge->pci_bus, PCI_MULTIFUNCTION, 
				     bus_num, pci_dev->dev_num, 3, 
				     "PIIX4-PM", bars, 
				     NULL, NULL, NULL, NULL, southbridge);
    if (pm_dev == NULL) {
	PrintError("Could not register PCI Device for PIIX4 PM subfunction\n");
	return -1;
    }

    pci_dev->config_header.vendor_id = 0x8086;
    pci_dev->config_header.device_id = 0x7113;  // PIIX4 PM subfunction
    pci_dev->config_header.class = PCI_CLASS_BRIDGE;
    pci_dev->config_header.subclass = PCI_BRIDGE_SUBCLASS_PCI_OTHER; 

    piix4->pm_subfunction = pm_dev;

    reset_piix4_pm(piix4);



    for (i = 0; i < 64; i++) {
	ret |= v3_dev_hook_io(dev, PIIX4_PM_BASE_PORT + i, &pm_read_port, &pm_write_port);
    }

    ret |= v3_dev_hook_io(dev, PIIX4_SMI_CMD_PORT, &smi_read_port, &smi_write_port);
    
    if (ret != 0) {
	PrintError("Error allocating IO hooks for PIIX PM subfunction\n");
	return -1;
    }


    

    return 0;
}

static int piix4_init(struct v3_vm_info * vm, v3_cfg_tree_t * cfg) {
    struct piix4_internal * piix4 = (struct piix4_internal *)V3_Malloc(sizeof(struct piix4_internal));
    struct v3_southbridge * southbridge = NULL;
    struct vm_device * dev = NULL;
    struct vm_device * pci = v3_find_dev(vm, v3_cfg_val(cfg, "bus"));
    char * dev_id = v3_cfg_val(cfg, "ID");

    if (!piix4) {
	PrintError("Cannot allocate in init\n");
	return -1;
    }



    if (!pci) {
	PrintError("Could not find PCI device\n");
	return -1;
    }

    southbridge =  &(piix4->southbridge);
   
    southbridge->pci_bus = pci;
    southbridge->type = V3_SB_PIIX4;
    southbridge->vm = vm;
    
    dev = v3_add_device(vm, dev_id, &dev_ops, southbridge);

    if (dev == NULL) {
	PrintError("Could not attach device %s\n", dev_id);
	V3_Free(piix4);
	return -1;
    }

    PrintDebug("Created PIIX4\n");

    if (setup_pci(dev) == -1) {
	v3_remove_device(dev);
	return -1;
    }


    return 0;
}


device_register("PIIX4", piix4_init)
