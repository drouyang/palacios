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

#ifndef __VMM_CTRL_REGS_H
#define __VMM_CTRL_REGS_H

#ifdef __V3VEE__


#include <palacios/vm.h>

#define EFER_MSR                 0xc0000080

struct cr0_real {
    uint32_t pe    : 1;
    uint32_t mp    : 1;
    uint32_t em    : 1;
    uint32_t ts    : 1;
} __attribute__((packed));


struct cr0_32 {
    uint32_t pe    : 1;
    uint32_t mp    : 1;
    uint32_t em    : 1;
    uint32_t ts    : 1;
    uint32_t et    : 1;
    uint32_t ne    : 1;
    uint32_t rsvd1 : 10;
    uint32_t wp    : 1;
    uint32_t rsvd2 : 1;
    uint32_t am    : 1;
    uint32_t rsvd3 : 10;
    uint32_t nw    : 1;
    uint32_t cd    : 1;
    uint32_t pg    : 1;
} __attribute__((packed));


struct cr0_64 {
    uint64_t pe    : 1;
    uint64_t mp    : 1;
    uint64_t em    : 1;
    uint64_t ts    : 1;
    uint64_t et    : 1;
    uint64_t ne    : 1;
    uint64_t rsvd1 : 10;
    uint64_t wp    : 1;
    uint64_t rsvd2 : 1;
    uint64_t am    : 1;
    uint64_t rsvd3 : 10;
    uint64_t nw    : 1;
    uint64_t cd    : 1;
    uint64_t pg    : 1;

    uint64_t rsvd4 : 32;  // MBZ
} __attribute__((packed));


struct cr2_32 {
    uint32_t pf_vaddr;
} __attribute__((packed));

struct cr2_64 {
    uint64_t pf_vaddr;
} __attribute__((packed));


struct cr3_32 {
    uint32_t rsvd1             : 3;
    uint32_t pwt               : 1;
    uint32_t pcd               : 1;
    uint32_t rsvd2             : 7;
    uint32_t pdt_base_addr    : 20;
} __attribute__((packed));


struct cr3_32_PAE {
    uint32_t rsvd1             : 3;
    uint32_t pwt               : 1;
    uint32_t pcd               : 1;
    uint32_t pdpt_base_addr    : 27;
} __attribute__((packed));


struct cr3_64 {
    uint64_t rsvd1             : 3;
    uint64_t pwt               : 1;
    uint64_t pcd               : 1;
    uint64_t rsvd2             : 7;
    uint64_t pml4t_base_addr   : 40;
    uint64_t rsvd3             : 12; 
} __attribute__((packed));


struct cr4_32 {
    uint32_t vme               : 1;
    uint32_t pvi               : 1;
    uint32_t tsd               : 1;
    uint32_t de                : 1;
    uint32_t pse               : 1;
    uint32_t pae               : 1;
    uint32_t mce               : 1;
    uint32_t pge               : 1;
    uint32_t pce               : 1;
    uint32_t osf_xsr           : 1;
    uint32_t osxmmexcpt        : 1;
    uint32_t rsvd1             : 2;
    uint32_t vmxe              : 1; /* Intel Only: VMX enabled */
    uint32_t smxe              : 1; /* Intel Only: SMX enabled */
    uint32_t rsvd2             : 1;
    uint32_t fsgsbase          : 1; /* Intel Only: Enables RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE instructions*/
    uint32_t pcide             : 1; /* Intel Only: Enables process context identifiers */
    uint32_t osxsave           : 1; /* Intel Only(?): Enabels OSXSAVE functionality */
    uint32_t rsvd3             : 1;
    uint32_t smep              : 1; /* Intel Only: Enables supervisor mode execution prevention */
    uint32_t rsvd4             : 11;
} __attribute__((packed));

struct cr4_64 {
    uint64_t vme               : 1;
    uint64_t pvi               : 1;
    uint64_t tsd               : 1;
    uint64_t de                : 1;
    uint64_t pse               : 1;
    uint64_t pae               : 1;
    uint64_t mce               : 1;
    uint64_t pge               : 1;
    uint64_t pce               : 1;
    uint64_t osf_xsr           : 1;
    uint64_t osxmmexcpt        : 1;
    uint64_t rsvd1             : 2;
    uint64_t vmxe              : 1; /* Intel Only: VMX enabled */
    uint64_t smxe              : 1; /* Intel Only: SMX enabled */
    uint64_t rsvd2             : 1;
    uint64_t fsgsbase          : 1; /* Intel Only: Enables RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE instructions*/
    uint64_t pcide             : 1; /* Intel Only: Enables process context identifiers */
    uint64_t osxsave           : 1; /* Intel Only(?): Enabels OSXSAVE functionality */
    uint64_t rsvd3             : 1;
    uint64_t smep              : 1; /* Intel Only: Enables supervisor mode execution prevention */
    uint64_t rsvd4             : 11;
    uint64_t rsvd5             : 32;
} __attribute__((packed));



struct efer_64 {
    uint64_t sce              : 1;
    uint64_t rsvd1            : 7; // RAZ
    uint64_t lme              : 1;
    uint64_t rsvd2            : 1; // MBZ
    uint64_t lma              : 1;
    uint64_t nxe              : 1;
    uint64_t svme             : 1;
    uint64_t rsvd3            : 1; // MBZ
    uint64_t ffxsr            : 1;
    uint64_t rsvd4            : 12; // MBZ
    uint64_t rsvd5            : 32; // MBZ
} __attribute__((packed));


struct rflags {
    uint64_t cf                : 1;  // carry flag
    uint64_t rsvd1             : 1;  // Must be 1
    uint64_t pf                : 1;  // parity flag
    uint64_t rsvd2             : 1;  // Read as 0
    uint64_t af                : 1;  // Auxillary flag
    uint64_t rsvd3             : 1;  // Read as 0
    uint64_t zf                : 1;  // zero flag
    uint64_t sf                : 1;  // sign flag
    uint64_t tf                : 1;  // trap flag
    uint64_t intr              : 1;  // interrupt flag
    uint64_t df                : 1;  // direction flag
    uint64_t of                : 1;  // overflow flag
    uint64_t iopl              : 2;  // IO privilege level
    uint64_t nt                : 1;  // nested task
    uint64_t rsvd4             : 1;  // read as 0
    uint64_t rf                : 1;  // resume flag
    uint64_t vm                : 1;  // Virtual-8086 mode
    uint64_t ac                : 1;  // alignment check
    uint64_t vif               : 1;  // virtual interrupt flag
    uint64_t vip               : 1;  // virtual interrupt pending
    uint64_t id                : 1;  // ID flag
    uint64_t rsvd5             : 10; // Read as 0
    uint64_t rsvd6             : 32; // Read as 0
} __attribute__((packed));





/*
// First opcode byte
static const uchar_t cr_access_byte = 0x0f;

// Second opcode byte
static const uchar_t lmsw_byte = 0x01;
static const uchar_t lmsw_reg_byte = 0x6;
static const uchar_t smsw_byte = 0x01;
static const uchar_t smsw_reg_byte = 0x4;
static const uchar_t clts_byte = 0x06;
static const uchar_t mov_to_cr_byte = 0x22;
static const uchar_t mov_from_cr_byte = 0x20;
*/


int v3_handle_cr0_write(struct v3_core_info * core);
int v3_handle_cr0_read(struct v3_core_info * core);

int v3_handle_cr3_write(struct v3_core_info * core);
int v3_handle_cr3_read(struct v3_core_info * core);

int v3_handle_cr4_write(struct v3_core_info * core);
int v3_handle_cr4_read(struct v3_core_info * core);


int v3_handle_efer_write(struct v3_core_info * core, uint_t msr, struct v3_msr src, void * priv_data);
int v3_handle_efer_read(struct v3_core_info * core, uint_t msr, struct v3_msr * dst, void * priv_data);

int v3_handle_vm_cr_write(struct v3_core_info * core, uint_t msr, struct v3_msr src, void * priv_data);
int v3_handle_vm_cr_read(struct v3_core_info * core, uint_t msr, struct v3_msr * dst, void * priv_data);


#endif // ! __V3VEE__


#endif
