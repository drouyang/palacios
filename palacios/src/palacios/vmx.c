/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2011, Jack Lange <jarusl@cs.northwestern.edu>
 * Copyright (c) 2011, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmx.h>
#include <palacios/vmm.h>
#include <palacios/vmx_handler.h>
#include <palacios/vmcs.h>
#include <palacios/vmx_lowlevel.h>
#include <palacios/vmm_lowlevel.h>
#include <palacios/vmm_ctrl_regs.h>
#include <palacios/vmm_config.h>
#include <palacios/vmm_time.h>
#include <palacios/vm_guest_mem.h>
#include <palacios/vmm_direct_paging.h>
#include <palacios/vmx_io.h>
#include <palacios/vmx_msr.h>
#include <palacios/vmm_decoder.h>
#include <palacios/vmm_barrier.h>
#include <palacios/vmm_timeout.h>
#include <palacios/vmm_debug.h>

#ifdef V3_CONFIG_CHECKPOINT
#include <palacios/vmm_checkpoint.h>
#endif

#include <palacios/vmx_ept.h>
#include <palacios/vmx_assist.h>
#include <palacios/vmx_hw_info.h>

#ifndef V3_CONFIG_DEBUG_VMX
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif


/* These fields contain the hardware feature sets supported by the local CPU */
static struct vmx_hw_info hw_info;

extern v3_cpu_arch_t v3_mach_type;

static addr_t host_vmcs_ptrs[V3_CONFIG_MAX_CPUS] = { [0 ... V3_CONFIG_MAX_CPUS - 1] = 0};

extern int v3_vmx_launch(struct v3_gprs * vm_regs, struct v3_core_info * core, struct v3_ctrl_regs * ctrl_regs);
extern int v3_vmx_resume(struct v3_gprs * vm_regs, struct v3_core_info * core, struct v3_ctrl_regs * ctrl_regs);





static addr_t 
allocate_vmcs() 
{
    struct vmcs_data * vmcs_page = NULL;
    void             * temp      = NULL;

    PrintDebug("Allocating page\n");

    temp = V3_AllocPages(1);
    if (!temp) { 
	PrintError("Cannot allocate VMCS\n");
	return -1;
    }
    vmcs_page = (struct vmcs_data *)V3_VAddr(temp);
    memset(vmcs_page, 0, 4096);

    vmcs_page->revision = hw_info.basic_info.revision;
    PrintDebug("VMX Revision: 0x%x\n", vmcs_page->revision);

    return (addr_t)V3_PAddr((void *)vmcs_page);
}


#if 0
static int 
debug_efer_read(struct v3_core_info * core, uint_t msr, struct v3_msr * src, void * priv_data) 
{
    struct v3_msr * efer = (struct v3_msr *)&(core->ctrl_regs.efer);
    V3_Print("\n\nEFER READ (val = %p)\n", (void *)efer->value);
    
    v3_print_guest_state(core);
    v3_print_vmcs();


    src->value = efer->value;
    return 0;
}

static int 
debug_efer_write(struct v3_core_info * core, uint_t msr, struct v3_msr src, void * priv_data) 
{
    struct v3_msr * efer = (struct v3_msr *)&(core->ctrl_regs.efer);
    V3_Print("\n\nEFER WRITE (old_val = %p) (new_val = %p)\n", (void *)efer->value, (void *)src.value);
    
    v3_print_guest_state(core);
    v3_print_vmcs();

    efer->value = src.value;

    return 0;
}
#endif


static int 
init_vmcs_bios(struct v3_core_info * core, struct vmx_data * vmx_state) 
{
    int vmx_ret = 0;

    // disable global interrupts for vm state initialization
    v3_disable_ints();

    PrintDebug("Loading VMCS\n");
    vmx_ret          = vmcs_load(vmx_state->vmcs_ptr_phys);
    vmx_state->state = VMX_UNLAUNCHED;

    if (vmx_ret != VMX_SUCCESS) {
        PrintError("VMPTRLD failed\n");
        return -1;
    }


    /*** Setup default state from HW ***/

    vmx_state->pin_ctrls.value       = hw_info.pin_ctrls.def_val;
    vmx_state->pri_proc_ctrls.value  = hw_info.proc_ctrls.def_val;
    vmx_state->exit_ctrls.value      = hw_info.exit_ctrls.def_val;
    vmx_state->entry_ctrls.value     = hw_info.entry_ctrls.def_val;
    vmx_state->sec_proc_ctrls.value  = hw_info.sec_proc_ctrls.def_val;

    /* Print Control MSRs */
    V3_Print("CR0 MSR: req_val=%p, req_mask=%p\n", 
	     (void *)(addr_t)hw_info.cr0.req_val, 
	     (void *)(addr_t)hw_info.cr0.req_mask);
    V3_Print("CR4 MSR: req_val=%p, req_mask=%p\n", 
	     (void *)(addr_t)hw_info.cr4.req_val, 
	     (void *)(addr_t)hw_info.cr4.req_mask);



    /******* Setup Host State **********/

    /* Cache GDTR, IDTR, and TR in host struct */


    /********** Setup VMX Control Fields ***********/

    /* Add external interrupts, NMI exiting, and virtual NMI */
    vmx_state->pin_ctrls.nmi_exit     = 1;
    vmx_state->pin_ctrls.virt_nmi     = 1;
    vmx_state->pin_ctrls.ext_int_exit = 1;


    /* We enable the preemption timer by default to measure accurate guest time */
    if (hw_info.caps.preempt_timer) {
	V3_Print("VMX Preemption Timer is available\n");
	vmx_state->pin_ctrls.active_preempt_timer = 1;
	vmx_state->exit_ctrls.save_preempt_timer  = 1;
    }

    // we want it to use this when halting
    vmx_state->pri_proc_ctrls.hlt_exit      = 1;

    // cpuid tells it that it does not have these instructions
    vmx_state->pri_proc_ctrls.monitor_exit  = 1;
    vmx_state->pri_proc_ctrls.mwait_exit    = 1;
    vmx_state->pri_proc_ctrls.pause_exit    = 0;
    vmx_state->pri_proc_ctrls.tsc_offset    = 1;

#ifdef V3_CONFIG_TIME_VIRTUALIZE_TSC
    vmx_state->pri_proc_ctrls.rdtsc_exit    = 1;
#endif

    /* Setup IO map */
    vmx_state->pri_proc_ctrls.use_io_bitmap = 1;

    vmx_ret |= check_vmcs_write(VMCS_IO_BITMAP_A_ADDR, 
				(addr_t)V3_PAddr(core->vm_info->io_map.arch_data));
    vmx_ret |= check_vmcs_write(VMCS_IO_BITMAP_B_ADDR, 
				(addr_t)V3_PAddr(core->vm_info->io_map.arch_data) + PAGE_SIZE_4KB);


    vmx_state->pri_proc_ctrls.use_msr_bitmap = 1;
    vmx_ret |= check_vmcs_write(VMCS_MSR_BITMAP, 
				(addr_t)V3_PAddr(core->vm_info->msr_map.arch_data));



#ifdef __V3_64BIT__
    // Ensure host runs in 64-bit mode at each VM EXIT
    vmx_state->exit_ctrls.host_64_on    = 1;
#endif

    if (hw_info.caps.virt_efer) {
	// Restore host's EFER register on each VM EXIT
	vmx_state->exit_ctrls.ld_efer   = 1;
	
	// Save/restore guest's EFER register to/from VMCS on VM EXIT/ENTRY
	vmx_state->exit_ctrls.save_efer = 1;
	vmx_state->entry_ctrls.ld_efer  = 1;
    }

    if (hw_info.caps.virt_pat) {
	vmx_state->exit_ctrls.save_pat = 1;
	vmx_state->exit_ctrls.ld_pat   = 1;
	vmx_state->entry_ctrls.ld_pat  = 1;

	// Setup Guests initial PAT field
	vmx_ret |= check_vmcs_write(VMCS_GUEST_PAT, 0x0007040600070406LL);
    }

    /* Temporary GPF trap */
    //  vmx_state->excp_bmap.gp = 1;

    //vmx_state->excp_bmap.ud = 1;


    /* Setup paging */
    if (core->shdw_pg_mode == SHADOW_PAGING) {
        PrintDebug("Creating initial shadow page table\n");

        if (v3_init_passthrough_pts(core) == -1) {
            PrintError("Could not initialize passthrough page tables\n");
            return -1;
        }
        
#define CR0_PE 0x00000001
#define CR0_PG 0x80000000
#define CR0_WP 0x00010000 // To ensure mem hooks work
#define CR0_NE 0x00000020
        vmx_ret |= check_vmcs_write(VMCS_CR0_MASK, (CR0_PE | CR0_PG | CR0_WP | CR0_NE));


	// Cause VM_EXIT whenever CR4.VMXE or CR4.PAE bits are written
	vmx_ret |= check_vmcs_write(VMCS_CR4_MASK, CR4_VMXE | CR4_PAE);

        core->ctrl_regs.cr3 = core->direct_map_pt;

        // vmx_state->pinbased_ctrls |= NMI_EXIT;

        /* Add CR exits */
        vmx_state->pri_proc_ctrls.cr3_ld_exit  = 1;
        vmx_state->pri_proc_ctrls.cr3_str_exit = 1;
	vmx_state->pri_proc_ctrls.invlpg_exit  = 1;
	
	/* Add page fault exits */
	vmx_state->excp_bmap.pf                = 1;

	// Setup VMX Assist
	v3_vmxassist_init(core, vmx_state);

	// Hook all accesses to EFER register
	v3_hook_msr(core->vm_info, EFER_MSR, 
		    &v3_handle_efer_read,
		    &v3_handle_efer_write, 
		    core);

    } else if ((core->shdw_pg_mode == NESTED_PAGING) && 
	       (v3_mach_type == V3_VMX_EPT_CPU)) {

#define CR0_PE 0x00000001
#define CR0_PG 0x80000000
#define CR0_WP 0x00010000 // To ensure mem hooks work
#define CR0_NE 0x00000020
        vmx_ret |= check_vmcs_write(VMCS_CR0_MASK, (CR0_PE | CR0_PG | CR0_WP | CR0_NE));

        // vmx_state->pinbased_ctrls |= NMI_EXIT;

	// Cause VM_EXIT whenever CR4.VMXE or CR4.PAE bits are written
	vmx_ret |= check_vmcs_write(VMCS_CR4_MASK, CR4_VMXE | CR4_PAE);
	
        /* Disable CR exits */
	vmx_state->pri_proc_ctrls.cr3_ld_exit  = 0;
	vmx_state->pri_proc_ctrls.cr3_str_exit = 0;
	vmx_state->pri_proc_ctrls.invlpg_exit  = 0;

	/* Add page fault exits */
	//	vmx_state->excp_bmap.pf = 1; // This should never happen..., enabled to catch bugs
	
	// Setup VMX Assist
	v3_vmxassist_init(core, vmx_state);

	/* Enable EPT */
	vmx_state->pri_proc_ctrls.sec_ctrls    = 1; // Enable secondary proc controls
	vmx_state->sec_proc_ctrls.enable_ept   = 1; // enable EPT paging
	vmx_state->sec_proc_ctrls.enable_vpid  = 1;
	check_vmcs_write(VMCS_VPID, 2);

	if (v3_init_ept(core, &hw_info) == -1) {
	    PrintError("Error initializing EPT\n");
	    return -1;
	}

	if (hw_info.caps.virt_efer) {
	    // Hook all accesses to EFER register
	    v3_hook_msr(core->vm_info, EFER_MSR, NULL, NULL, NULL);
	} else {
	    PrintError("Sweet merciful christ.... EFER virtualization not supported with EPT\n");
	    return -1;
	}

    } else if ((core->shdw_pg_mode == NESTED_PAGING) && 
	       (v3_mach_type == V3_VMX_EPT_UG_CPU)) {
	int i = 0;
	// For now we will assume that unrestricted guest mode is assured w/ EPT


	core->vm_regs.rsp      = 0x00;
	core->rip              = 0xfff0;
	core->vm_regs.rdx      = 0x00000f00;
	core->ctrl_regs.rflags = 0x00000002; // The reserved bit is always 1
	core->ctrl_regs.cr0    = 0x60010030; 
	core->ctrl_regs.cr4    = 0x00002010; // Enable VMX and PSE flag
	

	core->segments.cs.selector = 0xf000;
	core->segments.cs.limit    = 0xffff;
	core->segments.cs.base     = 0x0000000f0000LL;

	// (raw attributes = 0xf3)
	core->segments.cs.type     = 0xb;
	core->segments.cs.system   = 0x1;
	core->segments.cs.dpl      = 0x0;
	core->segments.cs.present  = 1;



	struct v3_segment * segregs [] = {&(core->segments.ss), &(core->segments.ds), 
					  &(core->segments.es), &(core->segments.fs), 
					  &(core->segments.gs), NULL};

	for ( i = 0; segregs[i] != NULL; i++) {
	    struct v3_segment * seg = segregs[i];
	
	    seg->selector = 0x0000;
	    // seg->base = seg->selector << 4;
	    seg->base     = 0x00000000;
	    seg->limit    = 0xffff;
	    seg->type     = 0x3;
	    seg->system   = 0x1;
	    seg->dpl      = 0x0;
	    seg->present  = 1;
	    //    seg->granularity = 1;

	}


	core->segments.gdtr.limit    = 0x0000ffff;
	core->segments.gdtr.base     = 0x0000000000000000LL;

	core->segments.idtr.limit    = 0x0000ffff;
	core->segments.idtr.base     = 0x0000000000000000LL;

	core->segments.ldtr.selector = 0x0000;
	core->segments.ldtr.limit    = 0x0000ffff;
	core->segments.ldtr.base     = 0x0000000000000000LL;
	core->segments.ldtr.type     = 0x2;
	core->segments.ldtr.present  = 1;

	core->segments.tr.selector   = 0x0000;
	core->segments.tr.limit      = 0x0000ffff;
	core->segments.tr.base       = 0x0000000000000000LL;
	core->segments.tr.type       = 0xb;
	core->segments.tr.present    = 1;

	// core->dbg_regs.dr6           = 0x00000000ffff0ff0LL;
	core->dbg_regs.dr7           = 0x0000000000000400LL;

	/* Enable EPT */
	vmx_state->pri_proc_ctrls.sec_ctrls      = 1; // Enable secondary proc controls
	vmx_state->sec_proc_ctrls.enable_ept     = 1; // enable EPT paging
	vmx_state->sec_proc_ctrls.unrstrct_guest = 1; // enable unrestricted guest operation


	vmx_state->sec_proc_ctrls.enable_vpid    = 1;
	check_vmcs_write(VMCS_VPID, 2);


	/* Disable shadow paging stuff */
	vmx_state->pri_proc_ctrls.cr3_ld_exit    = 0;
	vmx_state->pri_proc_ctrls.cr3_str_exit   = 0;
	vmx_state->pri_proc_ctrls.invlpg_exit    = 0;


	// Cause VM_EXIT whenever the CR4.VMXE bit is set
	vmx_ret |= check_vmcs_write(VMCS_CR4_MASK, CR4_VMXE);
#define CR0_NE 0x00000020
#define CR0_CD 0x40000000
	vmx_ret |= check_vmcs_write(VMCS_CR0_MASK, CR0_NE | CR0_CD);
	((struct cr0_32 *)&(core->shdw_pg_state.guest_cr0))->ne = 1;
	((struct cr0_32 *)&(core->shdw_pg_state.guest_cr0))->cd = 0;

	if (v3_init_ept(core, &hw_info) == -1) {
	    PrintError("Error initializing EPT\n");
	    return -1;
	}

	if (hw_info.caps.virt_efer) {
	    // Hook all accesses to EFER register
	    //	v3_hook_msr(core->vm_info, EFER_MSR, &debug_efer_read, &debug_efer_write, core);
	    v3_hook_msr(core->vm_info, EFER_MSR, NULL, NULL, NULL);
	} else {
	    PrintError("Sweet merciful christ.... EFER virtualization not supported with EPT\n");
	    return -1;
	}

    } else {
	PrintError("Invalid Virtual paging mode (pg_mode=%d) (mach_type=%d)\n", core->shdw_pg_mode, v3_mach_type);
	return -1;
    }


    // hook vmx msrs

    // Setup SYSCALL/SYSENTER MSRs in load/store area
    
    // save STAR, LSTAR, FMASK, KERNEL_GS_BASE MSRs in MSR load/store area
    {

	struct vmcs_msr_save_area * msr_entries = NULL;
	int max_msrs = (hw_info.misc_info.max_msr_cache_size + 1) * 4;
	int msr_ret = 0;

	V3_Print("Setting up MSR load/store areas (max_msr_count=%d)\n", max_msrs);

	if (max_msrs < 4) {
	    PrintError("Max MSR cache size is too small (%d)\n", max_msrs);
	    return -1;
	}

	vmx_state->msr_area_paddr = (addr_t)V3_AllocPages(1);
	
	if (vmx_state->msr_area_paddr == (addr_t)NULL) {
	    PrintError("could not allocate msr load/store area\n");
	    return -1;
	}

	msr_entries         = (struct vmcs_msr_save_area *)V3_VAddr((void *)(vmx_state->msr_area_paddr));
	vmx_state->msr_area = msr_entries; // cache in vmx_info

	memset(msr_entries, 0, PAGE_SIZE);

	msr_entries->guest_star.index    = IA32_STAR_MSR;
	msr_entries->guest_lstar.index   = IA32_LSTAR_MSR;
	msr_entries->guest_fmask.index   = IA32_FMASK_MSR;
	msr_entries->guest_kern_gs.index = IA32_KERN_GS_BASE_MSR;

	msr_entries->host_star.index     = IA32_STAR_MSR;
	msr_entries->host_lstar.index    = IA32_LSTAR_MSR;
	msr_entries->host_fmask.index    = IA32_FMASK_MSR;
	msr_entries->host_kern_gs.index  = IA32_KERN_GS_BASE_MSR;

	msr_ret |= check_vmcs_write(VMCS_EXIT_MSR_STORE_CNT, 4);
	msr_ret |= check_vmcs_write(VMCS_EXIT_MSR_LOAD_CNT,  4);
	msr_ret |= check_vmcs_write(VMCS_ENTRY_MSR_LOAD_CNT, 4);

	msr_ret |= check_vmcs_write(VMCS_EXIT_MSR_STORE_ADDR, (addr_t)V3_PAddr(msr_entries->guest_msrs));
	msr_ret |= check_vmcs_write(VMCS_ENTRY_MSR_LOAD_ADDR, (addr_t)V3_PAddr(msr_entries->guest_msrs));
	msr_ret |= check_vmcs_write(VMCS_EXIT_MSR_LOAD_ADDR,  (addr_t)V3_PAddr(msr_entries->host_msrs));


	msr_ret |= v3_hook_msr(core->vm_info, IA32_STAR_MSR,         NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, IA32_LSTAR_MSR,        NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, IA32_FMASK_MSR,        NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, IA32_KERN_GS_BASE_MSR, NULL, NULL, NULL);


	// IMPORTANT: These MSRs appear to be cached by the hardware....
	msr_ret |= v3_hook_msr(core->vm_info, SYSENTER_CS_MSR,  NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, SYSENTER_ESP_MSR, NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, SYSENTER_EIP_MSR, NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, FS_BASE_MSR,      NULL, NULL, NULL);
	msr_ret |= v3_hook_msr(core->vm_info, GS_BASE_MSR,      NULL, NULL, NULL);

	if (hw_info.caps.virt_pat) {
	    msr_ret |= v3_hook_msr(core->vm_info, IA32_PAT_MSR, NULL, NULL, NULL);
	} else {
	    // Handle these ops, and serialize on entry/exit
	    msr_ret |= v3_hook_msr(core->vm_info, IA32_PAT_MSR, NULL, NULL, NULL);
	}
	// Not sure what to do about this... Does not appear to be an explicit hardware cache version...
	msr_ret |= v3_hook_msr(core->vm_info, IA32_CSTAR_MSR,   NULL, NULL, NULL);

	if (msr_ret != 0) {
	    PrintError("Error configuring MSR save/restore area\n");
	    return -1;
	}


    }    


    /* Initialize FPU context. This is hacky and not well documented.... */
    v3_fpu_init(core);

    /* Sanity check ctrl/reg fields against hw_defaults */

    {
	int ret = 0;

	if ((vmx_state->pin_ctrls.value & hw_info.pin_ctrls.req_mask) != (hw_info.pin_ctrls.req_val)) {
	    PrintError("INTEL COMPAT ERROR: Pin Controls (val=0x%x, req_mask=0x%x, req_val=0x%x)\n", 
		       vmx_state->pin_ctrls.value, hw_info.pin_ctrls.req_mask, hw_info.pin_ctrls.req_val);
	    PrintError("Bit Errors: 0x%x\n", 
		       (vmx_state->pin_ctrls.value & hw_info.pin_ctrls.req_mask) ^ (hw_info.pin_ctrls.req_val));
	    ret = -1;
	}

	if ((vmx_state->pri_proc_ctrls.value & hw_info.proc_ctrls.req_mask) != (hw_info.proc_ctrls.req_val)) {
	    PrintError("INTEL COMPAT ERROR: Proc Controls (val=0x%x, req_mask=0x%x, req_val=0x%x)\n", 
		       vmx_state->pri_proc_ctrls.value, hw_info.proc_ctrls.req_mask, hw_info.proc_ctrls.req_val);
	    PrintError("Bit Errors: 0x%x\n", 
		       (vmx_state->pri_proc_ctrls.value & hw_info.proc_ctrls.req_mask) ^ (hw_info.proc_ctrls.req_val));
	    ret = -1;
	}

	if ((vmx_state->exit_ctrls.value & hw_info.exit_ctrls.req_mask) != (hw_info.exit_ctrls.req_val)) {
	    PrintError("INTEL COMPAT ERROR: Exit Controls (val=0x%x, req_mask=0x%x, req_val=0x%x)\n", 
		       vmx_state->exit_ctrls.value, hw_info.exit_ctrls.req_mask, hw_info.exit_ctrls.req_val);
	    PrintError("Bit Errors: 0x%x\n", 
		       (vmx_state->exit_ctrls.value & hw_info.exit_ctrls.req_mask) ^ (hw_info.exit_ctrls.req_val));
	    ret = -1;
	}

	if ((vmx_state->entry_ctrls.value & hw_info.entry_ctrls.req_mask) != (hw_info.entry_ctrls.req_val)) {
	    PrintError("INTEL COMPAT ERROR: Entry Controls (val=0x%x, req_mask=0x%x, req_val=0x%x)\n", 
		       vmx_state->entry_ctrls.value, hw_info.entry_ctrls.req_mask, hw_info.entry_ctrls.req_val);
	    PrintError("Bit Errors: 0x%x\n", 
		       (vmx_state->entry_ctrls.value & hw_info.entry_ctrls.req_mask) ^ (hw_info.entry_ctrls.req_val));
	    ret = -1;
	}

	if ((vmx_state->sec_proc_ctrls.value & hw_info.sec_proc_ctrls.req_mask) != (hw_info.sec_proc_ctrls.req_val)) {
	    PrintError("INTEL COMPAT ERROR: Sec Controls (val=0x%x, req_mask=0x%x, req_val=0x%x)\n", 
		       vmx_state->sec_proc_ctrls.value, hw_info.sec_proc_ctrls.req_mask, 
		       hw_info.sec_proc_ctrls.req_val);
	    PrintError("Bit Errors: 0x%x\n", 
		       (vmx_state->sec_proc_ctrls.value & hw_info.sec_proc_ctrls.req_mask) ^ (hw_info.sec_proc_ctrls.req_val));
	    ret = -1;
	}

	if ((core->ctrl_regs.cr0 & hw_info.cr0.req_mask) != (hw_info.cr0.req_val)) {
	    PrintError("INTEL COMPAT ERROR: CR0 (val=%p, req_mask=%p, req_val=%p)\n", 
		       (void *)core->ctrl_regs.cr0, 
		       (void *)hw_info.cr0.req_mask, 
		       (void *)hw_info.cr0.req_val);
	    PrintError("Bit Errors: 0x%llx\n", 
		       ((core->ctrl_regs.cr0 & hw_info.cr0.req_mask) ^ (hw_info.cr0.req_val)));
	    ret = -1;
	}

	if ((core->ctrl_regs.cr4 & hw_info.cr4.req_mask) != (hw_info.cr4.req_val)) {
	    PrintError("INTEL COMPAT ERROR: CR4 (val=%p, req_mask=%p, req_val=%p)\n", 
		       (void *)core->ctrl_regs.cr4, 
		       (void *)hw_info.cr4.req_mask, 
		       (void *)hw_info.cr4.req_val);
	    PrintError("Bit Errors: 0x%llx\n", 
		       ((core->ctrl_regs.cr4 & hw_info.cr4.req_mask) ^ (hw_info.cr4.req_val)));
	    ret = -1;
	}

	if (ret == -1) {
	    return -1;
	}
    }


    /*** Write all the info to the VMCS ***/
  
    /*
    {
	// IS THIS NECESSARY???
#define DEBUGCTL_MSR 0x1d9
	struct v3_msr tmp_msr;
	v3_get_msr(DEBUGCTL_MSR, &(tmp_msr.hi), &(tmp_msr.lo));
	vmx_ret |= check_vmcs_write(VMCS_GUEST_DBG_CTL, tmp_msr.value);
	core->dbg_regs.dr7 = 0x400;
    }
    */

#ifdef __V3_64BIT__
    vmx_ret |= check_vmcs_write(VMCS_LINK_PTR,      (addr_t)0xffffffffffffffffULL);
#else
    vmx_ret |= check_vmcs_write(VMCS_LINK_PTR,      (addr_t)0xffffffffUL);
    vmx_ret |= check_vmcs_write(VMCS_LINK_PTR_HIGH, (addr_t)0xffffffffUL);
#endif


 

    if (v3_update_vmcs_ctrl_fields(core)) {
        PrintError("Could not write control fields!\n");
        return -1;
    }
    
    /*
    if (v3_update_vmcs_host_state(core)) {
        PrintError("Could not write host state\n");
        return -1;
    }
    */

    // reenable global interrupts for vm state initialization now
    // that the vm state is initialized. If another VM kicks us off, 
    // it'll update our vmx state so that we know to reload ourself
    v3_enable_ints();

    return 0;
}


static void 
__init_vmx_vmcs(void * arg) 
{
    struct v3_core_info * core      = arg;
    struct vmx_data     * vmx_state = NULL;
    int vmx_ret = 0;
    
    vmx_state = (struct vmx_data *)V3_Malloc(sizeof(struct vmx_data));

    if (!vmx_state) {
	PrintError("Unable to allocate in initializing vmx vmcs\n");
	return;
    }

    memset(vmx_state, 0, sizeof(struct vmx_data));

    core->vmm_data           = vmx_state;
    vmx_state->state         = VMX_UNLAUNCHED;
    vmx_state->vmcs_ptr_phys = allocate_vmcs();
    
    /* Clear VMCS */
    vmx_ret = vmcs_clear(vmx_state->vmcs_ptr_phys);

    if (vmx_ret != VMX_SUCCESS) {
        PrintError("VMCLEAR failed (vmx_ret = %d)\n", vmx_ret);
        return; 
    }

    /* Initialize VMCS */
    if (core->vm_info->vm_class == V3_PC_VM) {
	if (init_vmcs_bios(core, vmx_state) == -1) {
	    PrintError("Error initializing VMCS to BIOS state\n");
	    return;
	}
    } else {
	PrintError("Invalid VM Class\n");
	return;
    }

    /* Serialize VMCS to HW */
    vmx_ret = vmcs_clear(vmx_state->vmcs_ptr_phys);

    core->core_run_state = CORE_STOPPED;
    return;
}



int 
v3_init_vmx_vmcs(struct v3_core_info * core, v3_vm_class_t vm_class) 
{
    extern v3_cpu_arch_t v3_cpu_types[];

    if (v3_cpu_types[V3_Get_CPU()] == V3_INVALID_CPU) {
	int i = 0;

	for (i = 0; i < V3_CONFIG_MAX_CPUS; i++) {
	    if (v3_cpu_types[i] != V3_INVALID_CPU) {
		break;
	    }
	}

	if (i == V3_CONFIG_MAX_CPUS) {
	    PrintError("Could not find VALID CPU for VMX guest initialization\n");
	    return -1;
	}

	V3_Call_On_CPU(i, __init_vmx_vmcs, core);

    } else {
	__init_vmx_vmcs(core);
    }

    if (core->core_run_state != CORE_STOPPED) {
	PrintError("Error initializing VMX Core\n");
	return -1;
    }

    return 0;
}


int 
v3_deinit_vmx_vmcs(struct v3_core_info * core) 
{
    struct vmx_data * vmx_state = core->vmm_data;

    V3_FreePages((void *)(vmx_state->vmcs_ptr_phys), 1);
    V3_FreePages(V3_PAddr(vmx_state->msr_area),      1);

    V3_Free(vmx_state);

    return 0;
}



#ifdef V3_CONFIG_CHECKPOINT
/* 
 * JRL: This is broken
 */
int 
v3_vmx_save_core(struct v3_core_info * core, void * ctx)
{
    struct vmx_data * vmx_info = (struct vmx_data *)(core->vmm_data);

    // note that the vmcs pointer is an HPA, but we need an HVA
    if (v3_chkpt_save(ctx, "vmcs_data", PAGE_SIZE_4KB, 
		      V3_VAddr((void*) (vmx_info->vmcs_ptr_phys))) ==-1) {
	PrintError("Could not save vmcs data for VMX\n");
	return -1;
    }

    return 0;
}

int 
v3_vmx_load_core(struct v3_core_info * core, void * ctx)
{
    struct vmx_data * vmx_info        = (struct vmx_data *)(core->vmm_data);
    struct cr0_32   * shadow_cr0      = NULL;
    addr_t            vmcs_page_paddr = 0;  //HPA

    vmcs_page_paddr = (addr_t) V3_AllocPages(1);
    
    if (!vmcs_page_paddr) { 
	PrintError("Could not allocate space for a vmcs in VMX\n");
	return -1;
    }

    if (v3_chkpt_load(ctx, "vmcs_data", PAGE_SIZE_4KB, 
		      V3_VAddr((void *)vmcs_page_paddr)) == -1) { 
	PrintError("Could not load vmcs data for VMX\n");
	return -1;
    }

    vmcs_clear(vmx_info->vmcs_ptr_phys);

    // Probably need to delete the old one... 
    V3_FreePages((void *)(vmx_info->vmcs_ptr_phys), 1);

    vmcs_load(vmcs_page_paddr);

    v3_vmx_save_vmcs(core, &hw_info);

    shadow_cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);


    /* Get the CPU mode to set the guest_ia32e entry ctrl */

    if (core->shdw_pg_mode == SHADOW_PAGING) {
	if (v3_get_vm_mem_mode(core) == VIRTUAL_MEM) {
	    if (v3_activate_shadow_pt(core) == -1) {
		PrintError("Failed to activate shadow page tables\n");
		return -1;
	    }
	} else {
	    if (v3_activate_passthrough_pt(core) == -1) {
		PrintError("Failed to activate passthrough page tables\n");
		return -1;
	    }
	}
    }

    return 0;
}
#endif


void 
v3_flush_vmx_vm_core(struct v3_core_info * core) 
{
    struct vmx_data * vmx_info = (struct vmx_data *)(core->vmm_data);

    vmcs_clear(vmx_info->vmcs_ptr_phys);
    vmx_info->state = VMX_UNLAUNCHED;
}



static int 
update_irq_exit_state(struct v3_core_info * core) 
{
    struct vmx_exit_idt_vec_info idt_vec_info;

    check_vmcs_read(VMCS_IDT_VECTOR_INFO, &(idt_vec_info.value));

    if ((core->intr_core_state.irq_started == 1) && (idt_vec_info.valid == 0)) {
#ifdef V3_CONFIG_DEBUG_INTERRUPTS
        V3_Print("Calling v3_injecting_intr\n");
#endif
        core->intr_core_state.irq_started = 0;
        v3_injecting_intr(core, core->intr_core_state.irq_vector, V3_EXTERNAL_IRQ);
    }

    return 0;
}

static int 
update_irq_entry_state(struct v3_core_info * core) 
{
    struct vmx_exit_idt_vec_info   idt_vec_info;
    struct vmcs_interrupt_state    vmcs_intr_state;
    struct vmx_data * vmx_info = (struct vmx_data *)(core->vmm_data);

    check_vmcs_read(VMCS_IDT_VECTOR_INFO, &(idt_vec_info.value));
    check_vmcs_read(VMCS_GUEST_INT_STATE, &(vmcs_intr_state));


    if (v3_excp_pending(core)) {
        struct vmx_entry_int_info int_info;
	uint32_t excp_vector = v3_get_excp_number(core);


	int_info.value  = 0;     /* Reset injection fields  */

	if (excp_vector == 2) {

	    /* NMI */
	    int_info.type   = 2;  /* NMIs have a special injection type (2)  */
	    int_info.vector = 0;  /* Vector is ignored                       */

	} else {
	    /*
	     * In VMX, almost every exception is hardware
	     * Software exceptions are pretty much only for breakpoint or overflow
	     */
	    int_info.type   = 3;              /* Set to HW Exception  */
	    int_info.vector = excp_vector;    /* Set vector           */

	}	    

	/*  Set error code if valid  */
	if (v3_excp_has_error(core, excp_vector)) {    
	    uint32_t excp_error = v3_get_excp_error(core, excp_vector);

	    check_vmcs_write(VMCS_ENTRY_EXCP_ERR, excp_error);
	    int_info.error_code = 1;
	    
#ifdef V3_CONFIG_DEBUG_INTERRUPTS
	    V3_Print("Injecting exception %d with error code %x\n", 
		     int_info.vector, excp_error);
#endif
	}
	    
        int_info.valid = 1;                                        /*  Mark as Valid  */

#ifdef V3_CONFIG_DEBUG_INTERRUPTS
        V3_Print("Injecting exception %d (EIP=%p)\n", excp_vector, (void *)(addr_t)core->rip);
#endif

        check_vmcs_write(VMCS_ENTRY_INT_INFO, int_info.value);     /* Serialize injection info to VMCS  */

        v3_injecting_excp(core, excp_vector);                      /* Signal that EXCP has been injected */


    } else if ((((struct rflags *)&(core->ctrl_regs.rflags))->intr == 1) &&    /* Guest has interrupts enabled       */
	       (vmcs_intr_state.val == 0)) {                                   /* VMCS intr blocking is not enabled  */
       
        if ((core->intr_core_state.irq_started == 1) &&              /* IRQ has previously been injected  */
	    (idt_vec_info.valid                == 1)) {              /* But, IRQ is still pending in VMCS */ 

#ifdef V3_CONFIG_DEBUG_INTERRUPTS
            V3_Print("IRQ pending from previous injection\n");
#endif

            // Copy the IDT vectoring info over to reinject the old interrupt
            if (idt_vec_info.error_code == 1) {
                uint32_t err_code = 0;

                check_vmcs_read( VMCS_IDT_VECTOR_ERR, &err_code);
                check_vmcs_write(VMCS_ENTRY_EXCP_ERR,  err_code);
            }

            idt_vec_info.undef = 0;
            check_vmcs_write(VMCS_ENTRY_INT_INFO, idt_vec_info.value);

        } else {                                                     /* Injecting a new IRQ */
            struct vmx_entry_int_info ent_int;
            ent_int.value = 0;                                       /* Clear irq entry fields */

            switch (v3_intr_pending(core)) {
                case V3_EXTERNAL_IRQ: {
                    core->intr_core_state.irq_vector = v3_get_intr(core);                 /* Cache vector in case we need to reinject (?) */
                    ent_int.vector                   = core->intr_core_state.irq_vector;  /* Set vector              */
                    ent_int.type                     = 0;                                 /* Set type to HW IRQ      */
                    ent_int.error_code               = 0;                                 /* No error codes for IRQs */
                    ent_int.valid                    = 1;                                 /* Mark entry as valid     */

#ifdef V3_CONFIG_DEBUG_INTERRUPTS
                    V3_Print("Injecting Interrupt %d at exit %u(EIP=%p)\n", 
			       core->intr_core_state.irq_vector, 
			       (uint32_t)core->num_exits, 
			       (void *)(addr_t)core->rip);
#endif

                    check_vmcs_write(VMCS_ENTRY_INT_INFO, ent_int.value);                 /* Serialize IRQ info to VMCS              */
                    core->intr_core_state.irq_started = 1;                                /* Record that we have begun IRQ injection */

                    break;
                }

                case V3_SOFTWARE_INTR:
                    PrintDebug("Injecting software interrupt\n");

                    ent_int.type  = 4;
                    ent_int.valid = 1;
                    check_vmcs_write(VMCS_ENTRY_INT_INFO, ent_int.value);

		    break;
                case V3_VIRTUAL_IRQ:
                    /* 
		     * Not sure what to do here, Intel doesn't have virtual IRQs
		     * Maybe the same as external interrupts/IRQs
		     */
		    break;
                case V3_INVALID_INTR:
                default:                          /* No IRQ pending, so we just drop out to end of function */
                    break; 
            }
        }
    } else if ((v3_intr_pending(core)) &&                                   /* There is an IRQ pending (But guest has IRQs disabled) */
	       (vmx_info->pri_proc_ctrls.int_wndw_exit == 0)) {             /* And IRQ window exiting is turned off                  */

	/* 
	 * At this point there is a pending interrupt, but the guest has IRQs disabled
	 *
	 * VMX does not allow injection in this case. Instead we have to force an exit as
	 * soon as they are turned back on by setting the intr window exiting control in the VMCS.
	 * This forces an exit immediately after IRQs are re-enabled, so we can retry the injection.
	 */

        uint32_t instr_len;
	
        check_vmcs_read(VMCS_EXIT_INSTR_LEN, &instr_len);

#ifdef V3_CONFIG_DEBUG_INTERRUPTS
        V3_Print("Enabling Interrupt-Window exiting: %d\n", instr_len);
#endif

        vmx_info->pri_proc_ctrls.int_wndw_exit = 1;
        check_vmcs_write(VMCS_PROC_CTRLS, vmx_info->pri_proc_ctrls.value);
    }


    return 0;
}



static struct vmx_exit_info exit_log[10];
static uint64_t  rip_log[10];



static void 
print_exit_log(struct v3_core_info * core) 
{
    int cnt = core->num_exits % 10;
    int i   = 0;
    

    V3_Print("\nExit Log (%d total exits):\n", (uint32_t)core->num_exits);

    for (i = 0; i < 10; i++) {
	struct vmx_exit_info * tmp = &exit_log[cnt];

	V3_Print("%d:\texit_reason    = %p\n", i, (void *)(addr_t)tmp->exit_reason);
	V3_Print("\texit_qual         = %p\n", (void *)tmp->exit_qual);
	V3_Print("\tint_info          = %p\n", (void *)(addr_t)tmp->int_info);
	V3_Print("\tint_err           = %p\n", (void *)(addr_t)tmp->int_err);
	V3_Print("\tinstr_info        = %p\n", (void *)(addr_t)tmp->instr_info);
	V3_Print("\tguest_linear_addr = %p\n", (void *)(addr_t)tmp->guest_linear_addr);
	V3_Print("\tRIP               = %p\n", (void *)rip_log[cnt]);


	cnt--;

	if (cnt == -1) {
	    cnt = 9;
	}

    }

}

int 
v3_vmx_config_tsc_virtualization(struct v3_core_info * core)
{
    struct vmx_data * vmx_info = (struct vmx_data *)(core->vmm_data);

    if (core->time_state.flags & VM_TIME_TRAP_RDTSC) {
	if (!vmx_info->pri_proc_ctrls.rdtsc_exit) {
	    vmx_info->pri_proc_ctrls.rdtsc_exit = 1;

	    check_vmcs_write(VMCS_PROC_CTRLS, vmx_info->pri_proc_ctrls.value);
	}
    } else {
        sint64_t tsc_offset;
        uint32_t tsc_offset_low, tsc_offset_high;

	if (vmx_info->pri_proc_ctrls.rdtsc_exit) {
	    vmx_info->pri_proc_ctrls.rdtsc_exit = 0;

	    check_vmcs_write(VMCS_PROC_CTRLS, vmx_info->pri_proc_ctrls.value);
	}

	if (core->time_state.flags & VM_TIME_TSC_PASSTHROUGH) {
	    tsc_offset  = 0;
	} else {
            tsc_offset  = v3_tsc_host_offset(&core->time_state);
	}
        tsc_offset_high = (uint32_t)((tsc_offset >> 32) & 0xffffffff);
        tsc_offset_low  = (uint32_t)((tsc_offset & 0xffffffff));

        check_vmcs_write(VMCS_TSC_OFFSET_HIGH, tsc_offset_high);
        check_vmcs_write(VMCS_TSC_OFFSET,      tsc_offset_low);
    }
    return 0;
}

/* 
 * CAUTION and DANGER!!! 
 * 
 * The VMCS CANNOT(!!) be accessed outside of the cli/sti calls inside this function
  */
int 
v3_vmx_enter(struct v3_core_info * core) 
{
    struct vmx_data    * vmx_info     = (struct vmx_data *)(core->vmm_data);
    uint64_t             guest_cycles = 0;
    struct vmx_exit_info exit_info;
    int ret = 0;

    // Conditionally yield the CPU if the timeslice has expired
    v3_yield_cond(core, -1);
    
    // Update timer devices late after being in the VM so that as much 
    // of the time in the VM is accounted for as possible. Also do it before
    // updating IRQ entry state so that any interrupts the timers raise get 
    // handled on the next VM entry.
    v3_advance_time(core, NULL);
    v3_update_timers(core);

    // disable global interrupts for vm state transition
    v3_disable_ints();

    if (vmcs_store() != vmx_info->vmcs_ptr_phys) {
	vmcs_clear(vmx_info->vmcs_ptr_phys);
	vmcs_load( vmx_info->vmcs_ptr_phys);
	vmx_info->state = VMX_UNLAUNCHED;
    }

    // Update FPU state, this must come before the guest state is serialized back to the VMCS
    v3_fpu_on_entry(core);

    v3_vmx_restore_vmcs(core, &hw_info);


    update_irq_entry_state(core);

    /*
    {
	addr_t guest_cr3;
	vmcs_read(VMCS_GUEST_CR3, &guest_cr3);
	vmcs_write(VMCS_GUEST_CR3, guest_cr3);
    }
    */

    // Perform last-minute time setup prior to entering the VM
    v3_vmx_config_tsc_virtualization(core);



    if (v3_update_vmcs_host_state(core, &hw_info)) {
	v3_enable_ints();
        PrintError("Could not write host state\n");
        return -1;
    }

    
    if (vmx_info->pin_ctrls.active_preempt_timer) {
	/* Preemption timer is active */
	uint32_t preempt_window = 0xffffffff;

	if (core->timeouts.timeout_active) {
	    preempt_window = core->timeouts.next_timeout;
	}
	
	check_vmcs_write(VMCS_PREEMPT_TIMER, preempt_window);
    }
   

    {	
	uint64_t entry_tsc = 0;
	uint64_t exit_tsc  = 0;

	if (vmx_info->state == VMX_UNLAUNCHED) {
	    vmx_info->state = VMX_LAUNCHED;
	    rdtscll(entry_tsc);
	    ret = v3_vmx_launch(&(core->vm_regs), core, &(core->ctrl_regs));
	    rdtscll(exit_tsc);

	} else {
	    V3_ASSERT(vmx_info->state != VMX_UNLAUNCHED);
	    rdtscll(entry_tsc);
	    ret = v3_vmx_resume(&(core->vm_regs), core, &(core->ctrl_regs));
	    rdtscll(exit_tsc);
	}

	guest_cycles                        = exit_tsc - entry_tsc;	
	core->time_state.time_in_guest     += guest_cycles;
	core->time_state.time_in_host      += ((exit_tsc - core->time_state.tsc_at_last_exit) - guest_cycles);
	core->time_state.tsc_at_last_entry  = entry_tsc;
	core->time_state.tsc_at_last_exit   = exit_tsc;
    }

    //  PrintDebug("VMX Exit: ret=%d\n", ret);

    if (ret != VMX_SUCCESS) {
	uint32_t error = 0;
        vmcs_read(VMCS_INSTR_ERR, &error);

	v3_enable_ints();

	PrintError("VMENTRY Error: %d (launch_ret = %d)\n", error, ret);
	return -1;
    }


    core->num_exits++;

    /* If we have the preemption time, then use it to get more accurate guest time */
    if (vmx_info->pin_ctrls.active_preempt_timer) {
	uint32_t cycles_left = 0;
	check_vmcs_read(VMCS_PREEMPT_TIMER, &(cycles_left));

	if (core->timeouts.timeout_active) {
	    guest_cycles = core->timeouts.next_timeout - cycles_left;
	} else {
	    guest_cycles = 0xffffffff - cycles_left;
	}
    }

    // Immediate exit from VM time bookkeeping
    v3_advance_time(core, &guest_cycles);

    /* Update guest state */
    v3_vmx_save_vmcs(core, &hw_info);

    // core->cpl = core->segments.cs.selector & 0x3;

    core->mem_mode = v3_get_vm_mem_mode(core);
    core->cpu_mode = v3_get_vm_cpu_mode(core);



    check_vmcs_read(VMCS_EXIT_INSTR_LEN,    &(exit_info.instr_len));
    check_vmcs_read(VMCS_EXIT_INSTR_INFO,   &(exit_info.instr_info));
    check_vmcs_read(VMCS_EXIT_REASON,       &(exit_info.exit_reason));
    check_vmcs_read(VMCS_EXIT_QUAL,         &(exit_info.exit_qual));
    check_vmcs_read(VMCS_EXIT_INT_INFO,     &(exit_info.int_info));
    check_vmcs_read(VMCS_EXIT_INT_ERR,      &(exit_info.int_err));
    check_vmcs_read(VMCS_GUEST_LINEAR_ADDR, &(exit_info.guest_linear_addr));

    if (core->shdw_pg_mode == NESTED_PAGING) {
	check_vmcs_read(VMCS_GUEST_PHYS_ADDR, &(exit_info.ept_fault_addr));
    }

    //PrintDebug("VMX Exit taken, id-qual: %u-%lu\n", exit_info.exit_reason, exit_info.exit_qual);

    exit_log[core->num_exits % 10] = exit_info;
    rip_log[core->num_exits % 10]  = get_addr_linear(core, core->rip, V3_SEG_CS);

    update_irq_exit_state(core);

    if (exit_info.exit_reason == VMX_EXIT_INTR_WINDOW) {
	// This is a special case whose only job is to inject an interrupt
	vmcs_read(VMCS_PROC_CTRLS,  &(vmx_info->pri_proc_ctrls.value));
        vmx_info->pri_proc_ctrls.int_wndw_exit = 0;
        vmcs_write(VMCS_PROC_CTRLS, vmx_info->pri_proc_ctrls.value);

#ifdef V3_CONFIG_DEBUG_INTERRUPTS
       V3_Print("Interrupts available again! (RIP=%llx)\n", core->rip);
#endif
    }


    // Lastly we check for an NMI exit, and reinject if so
    {
	struct vmx_basic_exit_info * basic_info = (struct vmx_basic_exit_info *)&(exit_info.exit_reason);

	if (basic_info->reason == VMX_EXIT_INFO_EXCEPTION_OR_NMI) {
	    if ((uint8_t)exit_info.int_info == 2) {
		asm("int $2");
	    }
	}
    }

    // reenable global interrupts after vm exit
    v3_enable_ints();

    // Conditionally yield the CPU if the timeslice has expired
    v3_yield_cond(core, -1);
   
    v3_advance_time(core, NULL);
    v3_update_timers(core);

    if (v3_handle_vmx_exit(core, &exit_info) == -1) {
	PrintError("Error in VMX exit handler (Exit reason=%x)\n", exit_info.exit_reason);
	return -1;
    }

    if (core->timeouts.timeout_active) {
	/* Check to see if any timeouts have expired */
	v3_handle_timeouts(core, guest_cycles);
    }

    return 0;
}


int 
v3_start_vmx_guest(struct v3_core_info * core) 
{

    V3_Print("Starting VMX core %u\n", core->vcpu_id);
    
    while (1) {

	if (core->core_run_state == CORE_STOPPED) {

	    if (v3_is_core_bsp(core)) {
		PrintDebug("BSP (core %d) is in STOPPED state, starting immediately\n", core->vcpu_id);
		core->core_run_state = CORE_RUNNING;
	    } else {
	    
		PrintDebug("VMX core %u is STOPPED: Waiting for core initialization\n", core->vcpu_id);

		while (core->core_run_state == CORE_STOPPED) {

		    if (core->vm_info->run_state == VM_STOPPED) {
			// The VM was stopped before this core was initialized. 
			return 0;
		    }




		    v3_yield(core, -1);
		    //PrintDebug("VMX core %u: still waiting for INIT\n",core->vcpu_id);
		}
	
		PrintDebug("VMX core %u initialized\n", core->vcpu_id);

		// We'll be paranoid about race conditions here
		v3_wait_at_barrier(core);
	    }


	    PrintDebug("VMX core %u: Starting at CS=0x%x (base=0x%p, limit=0x%x),  RIP=0x%p\n",
		       core->vcpu_id, core->segments.cs.selector, (void *)(core->segments.cs.base),
		       core->segments.cs.limit, (void *)(core->rip));


	    PrintDebug("VMX core %u: Launching VMX VM on logical core %u\n", core->vcpu_id, core->pcpu_id);

	    v3_start_time(core);
	}

	if (core->vm_info->run_state == VM_STOPPED) {
	    core->core_run_state = CORE_STOPPED;
	    break;
	}

	if (v3_vmx_enter(core) == -1) {

            core->vm_info->run_state = VM_ERROR;
            
            V3_Print("VMX core %u: VMX ERROR!!\n", core->vcpu_id); 
            
            v3_print_guest_state(core);
            
	    v3_print_vmcs();
	    print_exit_log(core);
	    return -1;
	}

	// Check for single step mode...
	if (core->brk_exit != 0) {
	    V3_Print("Single Stepping Guest: (entry_tsc=%llu) (exit_tsc=%llu)\n", 
		     core->time_state.tsc_at_last_entry,
		     core->time_state.tsc_at_last_exit);
	    
	    while ((core->num_exits >= core->brk_exit) && 
		   (core->brk_exit  != 0)) {
		v3_yield(core, -1);
		v3_wait_at_barrier(core);
	    }
	} else {
	    v3_wait_at_barrier(core);
	}

	if (core->vm_info->run_state == VM_STOPPED) {
	    core->core_run_state = CORE_STOPPED;
	    break;
	}
/*
	if ((core->num_exits % 5000) == 0) {
	    V3_Print("VMX Exit number %d\n", (uint32_t)core->num_exits);
	}
*/

    }

    return 0;
}




#define VMX_FEATURE_CONTROL_MSR     0x0000003a
#define CPUID_VMX_FEATURES          0x00000005  /* LOCK and VMXON */
#define CPUID_1_ECX_VTXFLAG         0x00000020

int 
v3_is_vmx_capable() 
{
    v3_msr_t feature_msr;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    v3_cpuid(0x1, &eax, &ebx, &ecx, &edx);

    PrintDebug("ECX: 0x%x\n", ecx);

    if (ecx & CPUID_1_ECX_VTXFLAG) {
        v3_get_msr(VMX_FEATURE_CONTROL_MSR, &(feature_msr.hi), &(feature_msr.lo));
	
        PrintDebug("MSRREGlow: 0x%.8x\n", feature_msr.lo);

        if ((feature_msr.lo & CPUID_VMX_FEATURES) != CPUID_VMX_FEATURES) {
            PrintDebug("VMX is locked -- enable in the BIOS\n");
            return 0;
        }

    } else {
        PrintDebug("VMX not supported on this cpu\n");
        return 0;
    }

    return 1;
}


int 
v3_reset_vmx_vm_core(struct v3_core_info * core, addr_t rip) 
{
    // init vmcs bios
    
    if ((core->shdw_pg_mode == NESTED_PAGING) && 
	(v3_mach_type       == V3_VMX_EPT_UG_CPU)) {
	// easy 
        core->rip = 0;
	core->segments.cs.selector = rip << 8;
	core->segments.cs.limit    = 0xffff;
	core->segments.cs.base     = rip << 12;
    } else {
	core->vm_regs.rdx          = core->vcpu_id;
	core->vm_regs.rbx          = rip;
    }

    return 0;
}



void 
v3_init_vmx_cpu(int cpu_id) 
{
    addr_t vmx_on_region = 0;
    extern v3_cpu_arch_t v3_mach_type;
    extern v3_cpu_arch_t v3_cpu_types[];

    if (v3_mach_type == V3_INVALID_CPU) {
	if (v3_init_vmx_hw(&hw_info) == -1) {
	    PrintError("Could not initialize VMX hardware features on cpu %d\n", cpu_id);
	    return;
	}
    }

    enable_vmx();


    // Setup VMXON Region
    vmx_on_region = allocate_vmcs();


    if (vmx_on(vmx_on_region) == VMX_SUCCESS) {
        V3_Print("VMX Enabled\n");
	host_vmcs_ptrs[cpu_id] = vmx_on_region;
    } else {
        V3_Print("VMX already enabled\n");
	V3_FreePages((void *)vmx_on_region, 1);
    }

    {
	if (hw_info.caps.ept == 0) {
	    V3_Print("VMX EPT (Nested) Paging not supported\n");
	    v3_cpu_types[cpu_id] = V3_VMX_CPU;
	} else if (hw_info.caps.unrestricted_guest == 0) {
	    V3_Print("VMX EPT (Nested) Paging supported\n");
	    v3_cpu_types[cpu_id] = V3_VMX_EPT_CPU;
	} else {
	    V3_Print("VMX EPT (Nested) Paging + Unrestricted guest supported\n");
	    v3_cpu_types[cpu_id] = V3_VMX_EPT_UG_CPU;
	}
    }
    
}


void
v3_deinit_vmx_cpu(int cpu_id) 
{
    extern v3_cpu_arch_t v3_cpu_types[];

    v3_cpu_types[cpu_id] = V3_INVALID_CPU;

    if (host_vmcs_ptrs[cpu_id] != 0) {
	V3_Print("Disabling VMX\n");

	if (vmx_off() != VMX_SUCCESS) {
	    PrintError("Error executing VMXOFF\n");
	}

	V3_FreePages((void *)host_vmcs_ptrs[cpu_id], 1);

	host_vmcs_ptrs[cpu_id] = 0;
    }
}
