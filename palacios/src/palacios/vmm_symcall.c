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

#include <palacios/vm.h>
#include <palacios/vmm_symcall.h>
#include <palacios/vmm_symspy.h>
#include <palacios/vmm_msr.h>

// A succesfull symcall returns via the RET_HCALL, with the return values in registers
// A symcall error returns via the ERR_HCALL with the error code in rbx


/* Notes: We use a combination of SYSCALL and SYSENTER Semantics 
 * SYSCALL just sets an EIP, CS/SS seg, and GS seg via swapgs
 * the RSP is loaded via the structure pointed to by GS
 * This is safe because it assumes that system calls are guaranteed to be made with an empty kernel stack.
 * We cannot make that assumption with a symcall, so we have to have our own stack area somewhere.
 * SYSTENTER does not really use the GS base MSRs, but we do to map to 64 bit kernels
 */

#define SYMCALL_RIP_MSR 0x536
#define SYMCALL_RSP_MSR 0x537
#define SYMCALL_CS_MSR  0x538
#define SYMCALL_GS_MSR  0x539
#define SYMCALL_FS_MSR  0x540


static int symcall_msr_read(struct v3_core_info * core, uint_t msr, 
			    struct v3_msr * dst, void * priv_data) {
    struct v3_symcall_state * state = &(core->sym_core_state.symcall_state);

    switch (msr) {
	case SYMCALL_RIP_MSR:
	    dst->value = state->sym_call_rip;
	    break;
	case SYMCALL_RSP_MSR:
	    dst->value = state->sym_call_rsp;
	    break;
	case SYMCALL_CS_MSR:
	    dst->value = state->sym_call_cs;
	    break;
	case SYMCALL_GS_MSR:
	    dst->value = state->sym_call_gs;
	    break;
	case SYMCALL_FS_MSR:
	    dst->value = state->sym_call_fs;
	    break;
	default:
	    return -1;
    }

    return 0;
}

static int symcall_msr_write(struct v3_core_info * core, uint_t msr, struct v3_msr src, void * priv_data) {
    struct v3_symcall_state * state = &(core->sym_core_state.symcall_state);

    switch (msr) {
	case SYMCALL_RIP_MSR:
	    state->sym_call_rip = src.value;
	    break;
	case SYMCALL_RSP_MSR:
	    state->sym_call_rsp = src.value;
	    break;
	case SYMCALL_CS_MSR:
	    state->sym_call_cs = src.value;
	    break;
	case SYMCALL_GS_MSR:
	    state->sym_call_gs = src.value;
	    break;
	case SYMCALL_FS_MSR:
	    state->sym_call_fs = src.value;
	    break;
	default:
	    PrintError("Invalid Symbiotic MSR write (0x%x)\n", msr);
	    return -1;
    }
    return 0;
}


static int sym_call_ret(struct v3_core_info * core, uint_t hcall_id, void * private_data);
static int sym_call_err(struct v3_core_info * core, uint_t hcall_id, void * private_data);




int v3_init_symcall_vm(struct v3_vm_info * vm) {

    v3_hook_msr(vm, SYMCALL_RIP_MSR, symcall_msr_read, symcall_msr_write, NULL);
    v3_hook_msr(vm, SYMCALL_RSP_MSR, symcall_msr_read, symcall_msr_write, NULL);
    v3_hook_msr(vm, SYMCALL_CS_MSR, symcall_msr_read, symcall_msr_write, NULL);
    v3_hook_msr(vm, SYMCALL_GS_MSR, symcall_msr_read, symcall_msr_write, NULL);
    v3_hook_msr(vm, SYMCALL_FS_MSR, symcall_msr_read, symcall_msr_write, NULL);

    v3_register_hypercall(vm, SYMCALL_RET_HCALL, sym_call_ret, NULL);
    v3_register_hypercall(vm, SYMCALL_ERR_HCALL, sym_call_err, NULL);


    return 0;
}





static int sym_call_err(struct v3_core_info * core, uint_t hcall_id, void * private_data) {
    struct v3_symcall_state * state = (struct v3_symcall_state *)&(core->sym_core_state.symcall_state);

    PrintError("sym call error\n");

    state->sym_call_errno = (int)core->vm_regs.rbx;
    v3_print_guest_state(core);
    v3_print_mem_map(core->vm_info);

    // clear sym flags
    state->sym_call_error = 1;
    state->sym_call_returned = 1;

    return -1;
}

static int sym_call_ret(struct v3_core_info * core, uint_t hcall_id, void * private_data) {
    struct v3_symcall_state * state = (struct v3_symcall_state *)&(core->sym_core_state.symcall_state);

    //    PrintError("Return from sym call (ID=%x)\n", hcall_id);
    //   v3_print_guest_state(info);

    state->sym_call_returned = 1;

    return 0;
}

static int execute_symcall(struct v3_core_info * core) {
    struct v3_symcall_state * state = (struct v3_symcall_state *)&(core->sym_core_state.symcall_state);

    while (state->sym_call_returned == 0) {
	if (v3_vm_enter(core) == -1) {
	    PrintError("Error in Sym call\n");
	    return -1;
	}
    }

    return 0;
}


//
// We don't handle those fancy 64 bit system segments...
//
static int translate_segment(struct v3_core_info * core, uint16_t selector, struct v3_segment * seg) {
    struct v3_segment * gdt = &(info->segments.gdtr);
    addr_t gdt_addr = 0;
    uint16_t seg_offset = (selector & ~0x7);
    addr_t seg_addr = 0;
    struct gen_segment * gen_seg = NULL;
    struct seg_selector sel;

    memset(seg, 0, sizeof(struct v3_segment));

    sel.value = selector;

    if (sel.ti == 1) {
	PrintError("LDT translations not supported\n");
	return -1;
    }

    if (v3_gva_to_hva(info, gdt->base, &gdt_addr) == -1) {
	PrintError("Unable to translate GDT address\n");
	return -1;
    }

    seg_addr = gdt_addr + seg_offset;
    gen_seg = (struct gen_segment *)seg_addr;

    //translate
    seg->selector = selector;

    seg->limit = gen_seg->limit_hi;
    seg->limit <<= 16;
    seg->limit += gen_seg->limit_lo;

    seg->base = gen_seg->base_hi;
    seg->base <<= 24;
    seg->base += gen_seg->base_lo;

    if (gen_seg->granularity == 1) {
	seg->limit <<= 12;
	seg->limit |= 0xfff;
    }

    seg->type = gen_seg->type;
    seg->system = gen_seg->system;
    seg->dpl = gen_seg->dpl;
    seg->present = gen_seg->present;
    seg->avail = gen_seg->avail;
    seg->long_mode = gen_seg->long_mode;
    seg->db = gen_seg->db;
    seg->granularity = gen_seg->granularity;
    
    return 0;
}



int v3_sym_call(struct v3_core_info * core, 
		uint64_t call_num, sym_arg_t * arg0, 
		sym_arg_t * arg1, sym_arg_t * arg2,
		sym_arg_t * arg3, sym_arg_t * arg4) {
    struct v3_symcall_state * state = (struct v3_symcall_state *)&(core->sym_core_state.symcall_state);
    struct v3_symspy_local_state * symspy_state = (struct v3_symspy_local_state *)&(core->sym_core_state.symspy_state);
    struct v3_sym_cpu_context * old_ctx = (struct v3_sym_cpu_context *)&(state->old_ctx);
    struct v3_segment sym_cs;
    struct v3_segment sym_ss;
    uint64_t trash_args[5] = { [0 ... 4] = 0 };

    //   PrintDebug("Making Sym call\n");
    //    v3_print_guest_state(info);

    if ((symspy_state->local_page->sym_call_enabled == 0) ||
	(symspy_state->local_page->sym_call_active == 1)) {
	return -1;
    }
    
    if (!arg0) arg0 = &trash_args[0];
    if (!arg1) arg1 = &trash_args[1];
    if (!arg2) arg2 = &trash_args[2];
    if (!arg3) arg3 = &trash_args[3];
    if (!arg4) arg4 = &trash_args[4];

    // Save the old context
    memcpy(&(old_ctx->vm_regs), &(core->vm_regs), sizeof(struct v3_gprs));
    memcpy(&(old_ctx->cs), &(core->segments.cs), sizeof(struct v3_segment));
    memcpy(&(old_ctx->ss), &(core->segments.ss), sizeof(struct v3_segment));
    old_ctx->gs_base = core->segments.gs.base;
    old_ctx->fs_base = core->segments.fs.base;
    old_ctx->rip = core->rip;
    old_ctx->cpl = core->cpl;
    old_ctx->flags = core->ctrl_regs.rflags;

    // Setup the sym call context
    core->rip = state->sym_call_rip;
    core->vm_regs.rsp = state->sym_call_rsp; // old contest rsp is saved in vm_regs

    translate_segment(core, state->sym_call_cs, &sym_cs);
    memcpy(&(core->segments.cs), &sym_cs, sizeof(struct v3_segment));
 
    translate_segment(core, state->sym_call_cs + 8, &sym_ss);
    memcpy(&(core->segments.ss), &sym_ss, sizeof(struct v3_segment));

    core->segments.gs.base = state->sym_call_gs;
    core->segments.fs.base = state->sym_call_fs;
    core->cpl = 0;

    core->vm_regs.rax = call_num;
    core->vm_regs.rbx = *arg0;
    core->vm_regs.rcx = *arg1;
    core->vm_regs.rdx = *arg2;
    core->vm_regs.rsi = *arg3;
    core->vm_regs.rdi = *arg4;

    // Mark sym call as active
    state->sym_call_active = 1;
    state->sym_call_returned = 0;

    //    PrintDebug("Sym state\n");
    //  v3_print_guest_state(core);

    // Do the sym call entry
    if (execute_symcall(core) == -1) {
	PrintError("SYMCALL error\n");
	return -1;
    }

    // clear sym flags
    state->sym_call_active = 0;

    *arg0 = core->vm_regs.rbx;
    *arg1 = core->vm_regs.rcx;
    *arg2 = core->vm_regs.rdx;
    *arg3 = core->vm_regs.rsi;
    *arg4 = core->vm_regs.rdi;

    // restore guest state
    memcpy(&(core->vm_regs), &(old_ctx->vm_regs), sizeof(struct v3_gprs));
    memcpy(&(core->segments.cs), &(old_ctx->cs), sizeof(struct v3_segment));
    memcpy(&(core->segments.ss), &(old_ctx->ss), sizeof(struct v3_segment));
    core->segments.gs.base = old_ctx->gs_base;
    core->segments.fs.base = old_ctx->fs_base;
    core->rip = old_ctx->rip;
    core->cpl = old_ctx->cpl;
    core->ctrl_regs.rflags = old_ctx->flags;



    //    PrintError("restoring guest state\n");
    //    v3_print_guest_state(core);

    return 0;
}


