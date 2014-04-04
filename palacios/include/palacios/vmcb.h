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

#ifndef __VMCB_H
#define __VMCB_H

#ifdef __V3VEE__

#include <palacios/vmm_types.h>
#include <palacios/vm.h>

#define VMCB_CTRL_AREA_OFFSET                   0x0
#define VMCB_STATE_SAVE_AREA_OFFSET             0x400


#define GET_VMCB_CTRL_AREA(page)         (page + VMCB_CTRL_AREA_OFFSET)
#define GET_VMCB_SAVE_STATE_AREA(page)   (page + VMCB_STATE_SAVE_AREA_OFFSET)



typedef void vmcb_t;


struct Ctrl_Registers {
    uint32_t cr0        : 1;
    uint32_t cr1        : 1;
    uint32_t cr2        : 1;
    uint32_t cr3        : 1;
    uint32_t cr4        : 1;
    uint32_t cr5        : 1;
    uint32_t cr6        : 1;
    uint32_t cr7        : 1;
    uint32_t cr8        : 1;
    uint32_t cr9        : 1;
    uint32_t cr10       : 1;
    uint32_t cr11       : 1;
    uint32_t cr12       : 1;
    uint32_t cr13       : 1;
    uint32_t cr14       : 1;
    uint32_t cr15       : 1;
} __attribute__((packed));


struct Debug_Registers {
    uint32_t dr0        : 1;
    uint32_t dr1        : 1;
    uint32_t dr2        : 1;
    uint32_t dr3        : 1;
    uint32_t dr4        : 1;
    uint32_t dr5        : 1;
    uint32_t dr6        : 1;
    uint32_t dr7        : 1;
    uint32_t dr8        : 1;
    uint32_t dr9        : 1;
    uint32_t dr10       : 1;
    uint32_t dr11       : 1;
    uint32_t dr12       : 1;
    uint32_t dr13       : 1;
    uint32_t dr14       : 1;
    uint32_t dr15       : 1;
} __attribute__((packed));


struct Exception_Vectors {
    uint32_t de          : 1; // (0) divide by zero
    uint32_t db          : 1; // (1) Debug
    uint32_t nmi         : 1; // (2) Non-maskable interrupt
    uint32_t bp          : 1; // (3) Breakpoint
    uint32_t of          : 1; // (4) Overflow
    uint32_t br          : 1; // (5) Bound-Range
    uint32_t ud          : 1; // (6) Invalid-Opcode
    uint32_t nm          : 1; // (7) Device-not-available
    uint32_t df          : 1; // (8) Double Fault
    uint32_t ex9         : 1; 
    uint32_t ts          : 1; // (10) Invalid TSS
    uint32_t np          : 1; // (11) Segment-not-present
    uint32_t ss          : 1; // (12) Stack
    uint32_t gp          : 1; // (13) General Protection Fault
    uint32_t pf          : 1; // (14) Page fault
    uint32_t ex15        : 1;
    uint32_t mf          : 1; // (15) Floating point exception
    uint32_t ac          : 1; // (16) Alignment-check
    uint32_t mc          : 1; // (17) Machine Check
    uint32_t xf          : 1; // (18) SIMD floating-point
    uint32_t ex20        : 1;
    uint32_t ex21        : 1;
    uint32_t ex22        : 1;
    uint32_t ex23        : 1;
    uint32_t ex24        : 1;
    uint32_t ex25        : 1;
    uint32_t ex26        : 1;
    uint32_t ex27        : 1;
    uint32_t ex28        : 1;
    uint32_t ex29        : 1;
    uint32_t sx          : 1; // (30) Security Exception
    uint32_t ex31        : 1;
} __attribute__((packed));


struct Instr_Intercepts {
    uint32_t INTR           : 1;
    uint32_t NMI            : 1;
    uint32_t SMI            : 1;
    uint32_t INIT           : 1;
    uint32_t VINTR          : 1;
    uint32_t CR0            : 1;
    uint32_t RD_IDTR        : 1;
    uint32_t RD_GDTR        : 1;
    uint32_t RD_LDTR        : 1;
    uint32_t RD_TR          : 1;
    uint32_t WR_IDTR        : 1;
    uint32_t WR_GDTR        : 1;
    uint32_t WR_LDTR        : 1;
    uint32_t WR_TR          : 1;
    uint32_t RDTSC          : 1;
    uint32_t RDPMC          : 1;
    uint32_t PUSHF          : 1;
    uint32_t POPF           : 1;
    uint32_t CPUID          : 1;
    uint32_t RSM            : 1;
    uint32_t IRET           : 1;
    uint32_t INTn           : 1;
    uint32_t INVD           : 1;
    uint32_t PAUSE          : 1;
    uint32_t HLT            : 1;
    uint32_t INVLPG         : 1;
    uint32_t INVLPGA        : 1;
    uint32_t IOIO_PROT      : 1;
    uint32_t MSR_PROT       : 1;
    uint32_t task_switch    : 1;
    uint32_t FERR_FREEZE    : 1;
    uint32_t shutdown_evts  : 1;
} __attribute__((packed));

struct SVM_Instr_Intercepts { 
    uint32_t VMRUN          : 1;
    uint32_t VMMCALL        : 1;
    uint32_t VMLOAD         : 1;
    uint32_t VMSAVE         : 1;
    uint32_t STGI           : 1;
    uint32_t CLGI           : 1;
    uint32_t SKINIT         : 1;
    uint32_t RDTSCP         : 1;
    uint32_t ICEBP          : 1;
    uint32_t WBINVD         : 1;
    uint32_t MONITOR        : 1;
    uint32_t MWAIT_always   : 1;
    uint32_t MWAIT_if_armed : 1;
    uint32_t reserved       : 19;  // Should be 0
} __attribute__((packed));


struct Guest_Control {
    uint32_t V_TPR           : 8;
    uint32_t V_IRQ           : 1;
    uint32_t rsvd1           : 7;  // Should be 0
    uint32_t V_INTR_PRIO     : 4;
    uint32_t V_IGN_TPR       : 1;
    uint32_t rsvd2           : 3;  // Should be 0
    uint32_t V_INTR_MASKING  : 1;
    uint32_t rsvd3           : 7;  // Should be 0
    uint32_t V_INTR_VECTOR   : 8;
    uint32_t rsvd4           : 24;  // Should be 0
} __attribute__((packed));

#define SVM_INJECTION_IRQ           0
#define SVM_INJECTION_NMI           2
#define SVM_INJECTION_EXCEPTION     3
#define SVM_INJECTION_SOFT_INTR     4

struct Interrupt_Info {
    uint64_t vector       : 8;
    uint64_t type         : 3;
    uint64_t ev           : 1;
    uint64_t rsvd         : 19;
    uint64_t valid        : 1;
    uint64_t error_code   : 32;
} __attribute__((packed));



struct VMCB_Control_Area {
    // offset 0x0
    struct Ctrl_Registers       cr_reads;
    struct Ctrl_Registers       cr_writes;
    struct Debug_Registers      dr_reads;
    struct Debug_Registers      dr_writes;
    struct Exception_Vectors    exceptions;
    struct Instr_Intercepts     instrs;
    struct SVM_Instr_Intercepts svm_instrs;

    uint8_t                     rsvd1[44];  // Should be 0

    // offset 0x040
    uint64_t IOPM_BASE_PA;
    uint64_t MSRPM_BASE_PA;
    uint64_t TSC_OFFSET;

    uint32_t guest_ASID;
    uint8_t  TLB_CONTROL;

    uint8_t  rsvd2[3];  // Should be 0

    struct Guest_Control guest_ctrl;
  
    uint32_t interrupt_shadow;
    uint32_t rsvd4;  // Should be 0

    uint64_t exit_code;
    uint64_t exit_info1;
    uint64_t exit_info2;

    /* This could be a typo in the manual....
     * It doesn't actually say that there is a reserved bit
     * But it does say that the EXITINTINFO field is in bits 63-1
     * ALL other occurances mention a 1 bit reserved field
     */
    //  uint_t rsvd5             : 1;
    //uint64_t exit_int_info   : 63;
    /* ** */

    // AMD Manual 2, pg 391, sect: 15.19
    struct Interrupt_Info exit_int_info;


    uint64_t NP_ENABLE;

    uint8_t  rsvd7[16];  // Should be 0

    // Offset 0xA8
    struct Interrupt_Info EVENTINJ;

    uint64_t N_CR3;
    uint64_t LBR_VIRTUALIZATION_ENABLE;


} __attribute__((packed));


typedef struct VMCB_Control_Area vmcb_ctrl_t;




struct vmcb_selector {
    uint16_t selector;

    /* These attributes are basically a direct map of the attribute fields of a segment desc.
     * The segment limit in the middle is removed and the fields are fused together
     * There IS empty space at the end... See AMD Arch vol3, sect. 4.7.1,  pg 78
     */
    union {
	uint16_t raw;
	struct {
	    uint16_t type              : 4; // segment type, [see Intel vol. 3b, sect. 3.4.5.1 (because I have the books)]
	    uint16_t S                 : 1; // System=0, code/data=1
	    uint16_t dpl               : 2; // priviledge level, corresonds to protection ring
	    uint16_t P                 : 1; // present flag
	    uint16_t avl               : 1; // available for use by system software
	    uint16_t L                 : 1; // long mode (64 bit?)
	    uint16_t db                : 1; // default op size (0=16 bit seg, 1=32 bit seg)
	    uint16_t G                 : 1; // Granularity, (0=bytes, 1=4k)
	    uint16_t rsvd              : 4;
	}  __attribute__((packed)) fields;
    }  __attribute__((packed)) attrib;

    uint32_t  limit;
    uint64_t  base;
}  __attribute__((packed));


struct VMCB_State_Save_Area {
    struct vmcb_selector es; // only lower 32 bits of base are implemented
    struct vmcb_selector cs; // only lower 32 bits of base are implemented
    struct vmcb_selector ss; // only lower 32 bits of base are implemented
    struct vmcb_selector ds; // only lower 32 bits of base are implemented
    struct vmcb_selector fs; 
    struct vmcb_selector gs; 

    struct vmcb_selector gdtr; // selector+attrib are reserved, only lower 16 bits of limit are implemented
    struct vmcb_selector ldtr; 
    struct vmcb_selector idtr; // selector+attrib are reserved, only lower 16 bits of limit are implemented
    struct vmcb_selector tr; 

    uint8_t  rsvd1[43];

    //offset 0x0cb
    uint8_t  cpl; // if the guest is real-mode then the CPL is forced to 0
    // if the guest is virtual-mode then the CPL is forced to 3

    uint32_t rsvd2;

    // offset 0x0d0
    uint64_t efer;

    uint8_t rsvd3[112];
  
    //offset 0x148
    uint64_t cr4;
    uint64_t cr3;
    uint64_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;

    uint8_t  rsvd4[88];
  
    //offset 0x1d8
    uint64_t rsp;

    uint8_t  rsvd5[24];

    //offset 0x1f8
    uint64_t rax;
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t KernelGsBase;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t cr2;


    uint8_t  rsvd6[32];

    //offset 0x268
    uint64_t g_pat;        /* Guest PAT                     (only used if nested paging is enabled)          */
    uint64_t dbgctl;       /* Guest DBGCTL MSR              (only used if the LBR registers are virtualized) */
    uint64_t br_from;      /* Guest LastBranchFromIP MSR    (only used if the LBR registers are virtualized) */
    uint64_t br_to;        /* Guest LastBranchToIP MSR      (only used if the LBR registers are virtualize)  */
    uint64_t lastexcpfrom; /* Guest LastExceptionFromIP MSR (only used if the LBR registers are virtualized) */
    uint64_t lastexcpto;   /* Guest LastExceptionToIP MSR   (only used if the LBR registers are virtualized) */

} __attribute__((packed));


typedef struct VMCB_State_Save_Area vmcb_saved_state_t;

void  v3_print_vmcb(vmcb_t * vmcb);


void v3_set_vmcb_segments(vmcb_t * vmcb, struct v3_segments * segs);
void v3_get_vmcb_segments(vmcb_t * vmcb, struct v3_segments * segs);

#endif // ! __V3VEE__

#endif
