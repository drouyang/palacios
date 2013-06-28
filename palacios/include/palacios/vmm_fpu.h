/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2013, Jack Lange <jacklange@cs.pitt.edu> 
 * Copyright (c) 2013, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#ifndef __VMM_FPU_H__
#define __VMM_FPU_H__

#ifdef __V3VEE__


#define XCR0_INIT_STATE 0x1


struct v3_fpu_arch {
    union {
	struct {
	    uint8_t fxstate[512];
	    uint8_t xsave_hdr[64];
	    /* potential future use */
	} __attribute__((packed));
	
	struct {
	    uint16_t cwd;
	    uint16_t swd;
	    uint16_t twd;
	    uint16_t fop;

	    uint64_t rip;
	    uint64_t rdp;

	    uint32_t mxcsr;
	    uint32_t mxcsr_mask;

	    uint32_t st_regs[32];
	    uint32_t xmm_regs[64];

	    uint32_t rsvd1[12];
	    uint32_t rsvd2[12];
	} __attribute__((packed));

    } __attribute__((packed));
} __attribute__((packed));



/* 
 * 
 * restore's occur whenever we get an NM exit. 
 * 
 */

struct v3_fpu_state {
    uint64_t guest_xcr0;
    uint64_t host_xcr0;


    struct {
	union {
	    uint8_t flags;

	    struct {
		uint8_t fpu_activated : 1;     /* We set this flag whenever the guest begins using the FPU, 
						* The flag is cleared whenever we save the state and re-enable traps for FPU accesses
						*/
		
		uint8_t disable_fpu_exits : 1; /* This flag indicates whether TS exits should bet set to trap on the next entry. 
						* When the exit is trapped we do a restore of the FPU, and mark it as activated 
						*/
		
		uint8_t enable_fpu_exits : 1;  /*
						*
						*/

		uint8_t last_ts_value : 1;
	    } __attribute__((packed));
	} __attribute__((packed));
    } __attribute__((packed));
    

    struct v3_fpu_arch arch_state;

};

int v3_fpu_init(struct guest_info * core);

int v3_fpu_on_entry(struct guest_info * core);


int v3_fpu_activate(struct guest_info * core);
int v3_fpu_deactivate(struct guest_info * core);


int v3_fpu_handle_xsetbv(struct guest_info * core);

#endif

#endif
