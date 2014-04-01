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

#include <palacios/vmcb.h>
#include <palacios/vmm.h>
#include <palacios/vmm_util.h>



void 
v3_set_vmcb_segment(struct vmcb_selector * vmcb_seg, struct v3_segment * seg, v3_seg_type_t seg_type) 
{
    vmcb_seg->selector           = seg->selector;
    vmcb_seg->limit              = seg->limit;
    vmcb_seg->base               = seg->base;
    vmcb_seg->attrib.fields.type = seg->type;
    vmcb_seg->attrib.fields.S    = seg->system;
    vmcb_seg->attrib.fields.dpl  = seg->dpl;
    vmcb_seg->attrib.fields.P    = seg->present;
    vmcb_seg->attrib.fields.avl  = seg->avail;
    vmcb_seg->attrib.fields.L    = seg->long_mode;
    vmcb_seg->attrib.fields.db   = seg->db;
    vmcb_seg->attrib.fields.G    = seg->granularity;



}


void 
v3_get_vmcb_segment(struct vmcb_selector * vmcb_seg, struct v3_segment * seg, v3_seg_type_t seg_type) 
{
    seg->selector    = vmcb_seg->selector;
    seg->limit       = vmcb_seg->limit;
    seg->base        = vmcb_seg->base;
    seg->type        = vmcb_seg->attrib.fields.type;
    seg->system      = vmcb_seg->attrib.fields.S;
    seg->dpl         = vmcb_seg->attrib.fields.dpl;
    seg->present     = vmcb_seg->attrib.fields.P;
    seg->avail       = vmcb_seg->attrib.fields.avl;
    seg->long_mode   = vmcb_seg->attrib.fields.L;
    seg->db          = vmcb_seg->attrib.fields.db;
    seg->granularity = vmcb_seg->attrib.fields.G;


    if ((seg_type == V3_SEG_DS) || (seg_type == V3_SEG_ES)) {
	/* Make sure the Segment accessed bit is always set. */
	if (seg->present) {
	    seg->type |= 0x1;
	} else {
	    // Clear the descriptor cache due to AMD weirdness...
	    seg->base  = 0;
	    seg->limit = 0xffffffff;
	}
    }

}



void 
v3_set_vmcb_segments(vmcb_t * vmcb, struct v3_segments * segs) 
{
    vmcb_saved_state_t * guest_area = GET_VMCB_SAVE_STATE_AREA(vmcb);

    v3_set_vmcb_segment(&(guest_area->cs),   &(segs->cs),   V3_SEG_CS);
    v3_set_vmcb_segment(&(guest_area->ds),   &(segs->ds),   V3_SEG_DS);
    v3_set_vmcb_segment(&(guest_area->es),   &(segs->es),   V3_SEG_ES);
    v3_set_vmcb_segment(&(guest_area->fs),   &(segs->fs),   V3_SEG_FS);
    v3_set_vmcb_segment(&(guest_area->gs),   &(segs->gs),   V3_SEG_GS);
    v3_set_vmcb_segment(&(guest_area->ss),   &(segs->ss),   V3_SEG_SS);
    v3_set_vmcb_segment(&(guest_area->ldtr), &(segs->ldtr), V3_SEG_LDTR);
    v3_set_vmcb_segment(&(guest_area->gdtr), &(segs->gdtr), V3_SEG_GDTR);
    v3_set_vmcb_segment(&(guest_area->idtr), &(segs->idtr), V3_SEG_IDTR);
    v3_set_vmcb_segment(&(guest_area->tr),   &(segs->tr),   V3_SEG_TR);
}


void 
v3_get_vmcb_segments(vmcb_t * vmcb, struct v3_segments * segs) 
{
    vmcb_saved_state_t * guest_area = GET_VMCB_SAVE_STATE_AREA(vmcb);

    v3_get_vmcb_segment(&(guest_area->cs),   &(segs->cs),   V3_SEG_CS);
    v3_get_vmcb_segment(&(guest_area->ds),   &(segs->ds),   V3_SEG_DS);
    v3_get_vmcb_segment(&(guest_area->es),   &(segs->es),   V3_SEG_ES);
    v3_get_vmcb_segment(&(guest_area->fs),   &(segs->fs),   V3_SEG_FS);
    v3_get_vmcb_segment(&(guest_area->gs),   &(segs->gs),   V3_SEG_GS);
    v3_get_vmcb_segment(&(guest_area->ss),   &(segs->ss),   V3_SEG_SS);
    v3_get_vmcb_segment(&(guest_area->ldtr), &(segs->ldtr), V3_SEG_LDTR);
    v3_get_vmcb_segment(&(guest_area->gdtr), &(segs->gdtr), V3_SEG_GDTR);
    v3_get_vmcb_segment(&(guest_area->idtr), &(segs->idtr), V3_SEG_IDTR);
    v3_get_vmcb_segment(&(guest_area->tr),   &(segs->tr),   V3_SEG_TR);
}


void 
v3_print_vmcb(vmcb_t * vmcb) 
{
    vmcb_ctrl_t        * ctrl_area  = GET_VMCB_CTRL_AREA(vmcb);
    vmcb_saved_state_t * guest_area = GET_VMCB_SAVE_STATE_AREA(vmcb);
    reg_ex_t tmp_reg;

    V3_Print("VMCB (0x%p)\n", (void *)vmcb);

    V3_Print("--Control Area--\n");
    V3_Print("CR Reads:  %x\n",  *(uint16_t*)&(ctrl_area->cr_reads));
    V3_Print("CR Writes: %x\n",  *(uint16_t*)&(ctrl_area->cr_writes));
    V3_Print("DR Reads:  %x\n",  *(uint16_t*)&(ctrl_area->dr_reads));
    V3_Print("DR Writes: %x\n",  *(uint16_t*)&(ctrl_area->dr_writes));
  
    /* Exception Exit Controls */
    V3_Print("Exception Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->exceptions), 
	        (void   *)&(ctrl_area->exceptions));
    V3_Print("\tDivide-by-Zero:       %d\n", ctrl_area->exceptions.de);
    V3_Print("\tDebug:                %d\n", ctrl_area->exceptions.db);
    V3_Print("\tNMIs                  %d\n", ctrl_area->exceptions.nmi);
    V3_Print("\tBreakpoint:           %d\n", ctrl_area->exceptions.bp);
    V3_Print("\tOverflow:             %d\n", ctrl_area->exceptions.of);
    V3_Print("\tBound-Range:          %d\n", ctrl_area->exceptions.br);
    V3_Print("\tInvalid Opcode:       %d\n", ctrl_area->exceptions.ud);
    V3_Print("\tDevice not available: %d\n", ctrl_area->exceptions.nm);
    V3_Print("\tDouble Fault:         %d\n", ctrl_area->exceptions.df);
    V3_Print("\tInvalid TSS:          %d\n", ctrl_area->exceptions.ts);
    V3_Print("\tSegment not present:  %d\n", ctrl_area->exceptions.np);
    V3_Print("\tStack:                %d\n", ctrl_area->exceptions.ss);
    V3_Print("\tGPF:                  %d\n", ctrl_area->exceptions.gp);
    V3_Print("\tPage Fault:           %d\n", ctrl_area->exceptions.pf);
    V3_Print("\tFloating Point:       %d\n", ctrl_area->exceptions.mf);
    V3_Print("\tAlignment Check:      %d\n", ctrl_area->exceptions.ac);
    V3_Print("\tMachine Check:        %d\n", ctrl_area->exceptions.mc);
    V3_Print("\tSIMD floating point:  %d\n", ctrl_area->exceptions.xf);
    V3_Print("\tSecurity:             %d\n", ctrl_area->exceptions.sx);

    /* Instruction Exit Controls */
    V3_Print("Instructions bitmap: %.8x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->instrs), 
	        (void   *)&(ctrl_area->instrs));
    V3_Print("\tINTR:                 %d\n", ctrl_area->instrs.INTR);
    V3_Print("\tNMI:                  %d\n", ctrl_area->instrs.NMI);
    V3_Print("\tSMI:                  %d\n", ctrl_area->instrs.SMI);
    V3_Print("\tINIT:                 %d\n", ctrl_area->instrs.INIT);
    V3_Print("\tVINTR:                %d\n", ctrl_area->instrs.VINTR);
    V3_Print("\tCR0:                  %d\n", ctrl_area->instrs.CR0);
    V3_Print("\tRD_IDTR:              %d\n", ctrl_area->instrs.RD_IDTR);
    V3_Print("\tRD_GDTR:              %d\n", ctrl_area->instrs.RD_GDTR);
    V3_Print("\tRD_LDTR:              %d\n", ctrl_area->instrs.RD_LDTR);
    V3_Print("\tRD_TR:                %d\n", ctrl_area->instrs.RD_TR);
    V3_Print("\tWR_IDTR:              %d\n", ctrl_area->instrs.WR_IDTR);
    V3_Print("\tWR_GDTR:              %d\n", ctrl_area->instrs.WR_GDTR);
    V3_Print("\tWR_LDTR:              %d\n", ctrl_area->instrs.WR_LDTR);
    V3_Print("\tWR_TR:                %d\n", ctrl_area->instrs.WR_TR);
    V3_Print("\tRDTSC:                %d\n", ctrl_area->instrs.RDTSC);
    V3_Print("\tRDPMC:                %d\n", ctrl_area->instrs.RDPMC);
    V3_Print("\tPUSHF:                %d\n", ctrl_area->instrs.PUSHF);
    V3_Print("\tPOPF:                 %d\n", ctrl_area->instrs.POPF);
    V3_Print("\tCPUID:                %d\n", ctrl_area->instrs.CPUID);
    V3_Print("\tRSM:                  %d\n", ctrl_area->instrs.RSM);
    V3_Print("\tIRET:                 %d\n", ctrl_area->instrs.IRET);
    V3_Print("\tINTn:                 %d\n", ctrl_area->instrs.INTn);
    V3_Print("\tINVD:                 %d\n", ctrl_area->instrs.INVD);
    V3_Print("\tPAUSE:                %d\n", ctrl_area->instrs.PAUSE);
    V3_Print("\tHLT:                  %d\n", ctrl_area->instrs.HLT);
    V3_Print("\tINVLPG:               %d\n", ctrl_area->instrs.INVLPG);
    V3_Print("\tINVLPGA:              %d\n", ctrl_area->instrs.INVLPGA);
    V3_Print("\tIOIO_PROT:            %d\n", ctrl_area->instrs.IOIO_PROT);
    V3_Print("\tMSR_PROT:             %d\n", ctrl_area->instrs.MSR_PROT);
    V3_Print("\ttask_switch:          %d\n", ctrl_area->instrs.task_switch);
    V3_Print("\tFERR_FREEZE:          %d\n", ctrl_area->instrs.FERR_FREEZE);
    V3_Print("\tshutdown_evts:        %d\n", ctrl_area->instrs.shutdown_evts);

    /* SVM Instruction Control */
    V3_Print("SVM Instruction Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->svm_instrs), 
	        (void   *)&(ctrl_area->svm_instrs));
    V3_Print("\tVMRUN:                %d\n", ctrl_area->svm_instrs.VMRUN);
    V3_Print("\tVMMCALL:              %d\n", ctrl_area->svm_instrs.VMMCALL);
    V3_Print("\tVMLOAD:               %d\n", ctrl_area->svm_instrs.VMLOAD);
    V3_Print("\tVMSAVE:               %d\n", ctrl_area->svm_instrs.VMSAVE);
    V3_Print("\tSTGI:                 %d\n", ctrl_area->svm_instrs.STGI);
    V3_Print("\tCLGI:                 %d\n", ctrl_area->svm_instrs.CLGI);
    V3_Print("\tSKINIT:               %d\n", ctrl_area->svm_instrs.SKINIT);
    V3_Print("\tRDTSCP:               %d\n", ctrl_area->svm_instrs.RDTSCP);
    V3_Print("\tICEBP:                %d\n", ctrl_area->svm_instrs.ICEBP);
    V3_Print("\tWBINVD:               %d\n", ctrl_area->svm_instrs.WBINVD);
    V3_Print("\tMONITOR:              %d\n", ctrl_area->svm_instrs.MONITOR);
    V3_Print("\tMWAIT_always:         %d\n", ctrl_area->svm_instrs.MWAIT_always);
    V3_Print("\tMWAIT_if_armed:       %d\n", ctrl_area->svm_instrs.MWAIT_if_armed);


    /* IO Port Bitmap Physical Address */
    V3_Print("IOPM_BASE_PA:  %p\n",   (void *)ctrl_area->IOPM_BASE_PA);

    /* MSR Bitmap Physical Address */
    V3_Print("MSRPM_BASE_PA: %p\n",   (void *)ctrl_area->MSRPM_BASE_PA);

    /* TSC Offset */
    V3_Print("TSC_OFFSET:    %llu\n", ctrl_area->TSC_OFFSET);

    V3_Print("guest_ASID:    %d\n",   ctrl_area->guest_ASID);
    V3_Print("TLB_CONTROL:   %d\n",   ctrl_area->TLB_CONTROL);


    /* Guest Controls */
    V3_Print("Guest Control Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->guest_ctrl), 
	        (void   *)&(ctrl_area->guest_ctrl));
    V3_Print("\tV_TPR:               %d\n", ctrl_area->guest_ctrl.V_TPR);
    V3_Print("\tV_IRQ:               %d\n", ctrl_area->guest_ctrl.V_IRQ);
    V3_Print("\tV_INTR_PRIO:         %d\n", ctrl_area->guest_ctrl.V_INTR_PRIO);
    V3_Print("\tV_IGN_TPR:           %d\n", ctrl_area->guest_ctrl.V_IGN_TPR);
    V3_Print("\tV_INTR_MASKING:      %d\n", ctrl_area->guest_ctrl.V_INTR_MASKING);
    V3_Print("\tV_INTR_VECTOR:       %d\n", ctrl_area->guest_ctrl.V_INTR_VECTOR);

    /* Exit Information */
    V3_Print("Interrupt_shadow:    %d\n",   ctrl_area->interrupt_shadow);
    V3_Print("exit_code:           %llu\n", ctrl_area->exit_code);
    V3_Print("exit_info1:          %llu\n", ctrl_area->exit_info1);
    V3_Print("exit_info2:          %llu\n", ctrl_area->exit_info2);


    /* Interrupt Injection State */
    V3_Print("Exit Int Info: (at 0x%p)\n", 
	       (void *)&(ctrl_area->exit_int_info));
    V3_Print("\tVector:     %d\n",  ctrl_area->exit_int_info.vector);
    V3_Print("\t    (type=%d) (ev=%d) (valid=%d)\n", 
	                            ctrl_area->exit_int_info.type, 
	                            ctrl_area->exit_int_info.ev, 
                                    ctrl_area->exit_int_info.valid);
    V3_Print("\tError Code: %d\n",  ctrl_area->exit_int_info.error_code);

    /* Exception Injection State */
    V3_Print("Event Injection: (at 0x%p)\n", 
	       (void *)&(ctrl_area->EVENTINJ));
    V3_Print("\tVector: %d\n",      ctrl_area->EVENTINJ.vector);
    V3_Print("\t    (type=%d) (ev=%d) (valid=%d)\n", 
	                            ctrl_area->EVENTINJ.type, 
	                            ctrl_area->EVENTINJ.ev, 
                                    ctrl_area->EVENTINJ.valid);
    V3_Print("\tError Code: %d\n",  ctrl_area->EVENTINJ.error_code);



    V3_Print("LBR_VIRTUALIZATION_ENABLE: %d\n",   ctrl_area->LBR_VIRTUALIZATION_ENABLE);
    V3_Print("NP_ENABLE:                 %llu\n", ctrl_area->NP_ENABLE);
    V3_Print("N_CR3:                     %p\n",   (void *)ctrl_area->N_CR3);



    V3_Print("\n--Guest Saved State--\n");

    
    /* 
     * Cached Segment Descriptors 
     */


    /* CS Segment */
    V3_Print("CS Selector (at 0x%p): \n", (void *)&(guest_area->cs));
    V3_Print("\tSelector: %d\n",      guest_area->cs.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->cs.attrib.fields.type, 
	                              guest_area->cs.attrib.fields.S, 
	                              guest_area->cs.attrib.fields.dpl, 
	                              guest_area->cs.attrib.fields.P,
	                              guest_area->cs.attrib.fields.avl,  
	                              guest_area->cs.attrib.fields.L,
	                              guest_area->cs.attrib.fields.db,   
	                              guest_area->cs.attrib.fields.G);
    V3_Print("\tLimit:    %u\n",      guest_area->cs.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->cs.base);

    /* SS Segment */
    V3_Print("SS Selector (at 0x%p): \n", (void *)&(guest_area->ss));
    V3_Print("\tSelector: %d\n",      guest_area->ss.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->ss.attrib.fields.type, 
	                              guest_area->ss.attrib.fields.S, 
	                              guest_area->ss.attrib.fields.dpl, 
	                              guest_area->ss.attrib.fields.P,
	                              guest_area->ss.attrib.fields.avl,
	                              guest_area->ss.attrib.fields.L,
	                              guest_area->ss.attrib.fields.db, 
	                              guest_area->ss.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->ss.limit);
    V3_Print("\tBase:     0x%llu\n",  guest_area->ss.base);


    /* DS Segment */
    V3_Print("DS Selector (at 0x%p): \n", (void *)&(guest_area->ds));
    V3_Print("\tSelector: %d\n",      guest_area->ds.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->ds.attrib.fields.type,
	                              guest_area->ds.attrib.fields.S, 
	                              guest_area->ds.attrib.fields.dpl, 
	                              guest_area->ds.attrib.fields.P,
	                              guest_area->ds.attrib.fields.avl, 
	                              guest_area->ds.attrib.fields.L,
	                              guest_area->ds.attrib.fields.db, 
	                              guest_area->ds.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->ds.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->ds.base);
 
    /* ES Segment */
    V3_Print("ES Selector (at 0x%p): \n", (void *)&(guest_area->es));
    V3_Print("\tSelector: %d\n",      guest_area->es.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->es.attrib.fields.type, 
                                      guest_area->es.attrib.fields.S, 
	                              guest_area->es.attrib.fields.dpl, 
                                      guest_area->es.attrib.fields.P,
	                              guest_area->es.attrib.fields.avl, 
                                      guest_area->es.attrib.fields.L,
	                              guest_area->es.attrib.fields.db, 
	                              guest_area->es.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->es.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->es.base);

    /* FS Segment */
    V3_Print("FS Selector (at 0x%p): \n", (void *)&(guest_area->fs));
    V3_Print("\tSelector: %d\n",      guest_area->fs.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->fs.attrib.fields.type, 
	                              guest_area->fs.attrib.fields.S, 
	                              guest_area->fs.attrib.fields.dpl, 
	                              guest_area->fs.attrib.fields.P,
	                              guest_area->fs.attrib.fields.avl, 
	                              guest_area->fs.attrib.fields.L,
	                              guest_area->fs.attrib.fields.db, 
	                              guest_area->fs.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->fs.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->fs.base);

    /* GS Segment */
    V3_Print("GS Selector (at 0x%p): \n", (void *)&(guest_area->gs));
    V3_Print("\tSelector: %d\n",      guest_area->gs.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->gs.attrib.fields.type, 
	                              guest_area->gs.attrib.fields.S, 
	                              guest_area->gs.attrib.fields.dpl, 
	                              guest_area->gs.attrib.fields.P,
	                              guest_area->gs.attrib.fields.avl, 
	                              guest_area->gs.attrib.fields.L,
	                              guest_area->gs.attrib.fields.db, 
	                              guest_area->gs.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->gs.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->gs.base);


    /* GDTR Segment Descriptor */
    V3_Print("GDTR Selector (at 0x%p): \n", (void *)&(guest_area->gdtr));
    V3_Print("\tSelector: %d\n",      guest_area->gdtr.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->gdtr.attrib.fields.type, 
	                              guest_area->gdtr.attrib.fields.S, 
	                              guest_area->gdtr.attrib.fields.dpl,
	                              guest_area->gdtr.attrib.fields.P,
	                              guest_area->gdtr.attrib.fields.avl, 
	                              guest_area->gdtr.attrib.fields.L,
	                              guest_area->gdtr.attrib.fields.db, 
	                              guest_area->gdtr.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->gdtr.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->gdtr.base);


    /* LDTR Segment Descriptor */
    V3_Print("LDTR Selector (at 0x%p): \n", (void *)&(guest_area->ldtr));
    V3_Print("\tSelector: %d\n",      guest_area->ldtr.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->ldtr.attrib.fields.type, 
	                              guest_area->ldtr.attrib.fields.S, 
	                              guest_area->ldtr.attrib.fields.dpl, 
	                              guest_area->ldtr.attrib.fields.P,
	                              guest_area->ldtr.attrib.fields.avl, 
	                              guest_area->ldtr.attrib.fields.L,
	                              guest_area->ldtr.attrib.fields.db, 
	                              guest_area->ldtr.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->ldtr.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->ldtr.base);


    /* IDTR Segment Descriptor */
    V3_Print("IDTR Selector (at 0x%p): \n", (void *)&(guest_area->idtr));
    V3_Print("\tSelector: %d\n",      guest_area->idtr.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->idtr.attrib.fields.type, 
	                              guest_area->idtr.attrib.fields.S, 
	                              guest_area->idtr.attrib.fields.dpl, 
	                              guest_area->idtr.attrib.fields.P,
	                              guest_area->idtr.attrib.fields.avl, 
	                              guest_area->idtr.attrib.fields.L,
	                              guest_area->idtr.attrib.fields.db, 
	                              guest_area->idtr.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->idtr.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->idtr.base);

    
    /* TR Segment Descriptor */
    V3_Print("TR Selector (at 0x%p): \n", (void *)&(guest_area->tr));
    V3_Print("\tSelector: %d\n",      guest_area->tr.selector); 
    V3_Print("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                              guest_area->tr.attrib.fields.type, 
	                              guest_area->tr.attrib.fields.S, 
	                              guest_area->tr.attrib.fields.dpl, 
	                              guest_area->tr.attrib.fields.P,
	                              guest_area->tr.attrib.fields.avl, 
	                              guest_area->tr.attrib.fields.L,
	                              guest_area->tr.attrib.fields.db, 
	                              guest_area->tr.attrib.fields.G);
    V3_Print("\tlimit:    %u\n",      guest_area->tr.limit);
    V3_Print("\tBase:     0x%llx\n",  guest_area->tr.base);


    /* The current CPL is cached in the VMCB */
    V3_Print("cpl:    %d\n", guest_area->cpl);

    /* Control Registers */
    V3_Print("RIP:             %p\n", (void *)guest_area->rip);
    V3_Print("RSP              %p\n", (void *)guest_area->rsp);
    V3_Print("RFLAGS:          %p\n", (void *)guest_area->rflags);
    V3_Print("EFER:            %p\n", (void *)guest_area->efer);
    V3_Print("CR0:             %p\n", (void *)guest_area->cr0);
    V3_Print("CR2:             %p\n", (void *)guest_area->cr2);
    V3_Print("CR3:             %p\n", (void *)guest_area->cr3);
    V3_Print("CR4:             %p\n", (void *)guest_area->cr4);
    V3_Print("DR7:             %p\n", (void *)guest_area->dr7);
    V3_Print("DR6:             %p\n", (void *)guest_area->dr6);
    V3_Print("g_pat:           %p\n", (void *)guest_area->g_pat);


    /* Only the RAX GPR is stored in the VMCB */
    V3_Print("RAX:             %p\n", (void *)guest_area->rax);

    /* System Call Registers */
    V3_Print("STAR:            %p\n", (void *)guest_area->star);
    V3_Print("LSTAR:           %p\n", (void *)guest_area->lstar);
    V3_Print("CSTAR:           %p\n", (void *)guest_area->cstar);
    V3_Print("SFMASK:          %p\n", (void *)guest_area->sfmask);
    V3_Print("KernelGsBase:    %p\n", (void *)guest_area->KernelGsBase);
    V3_Print("sysenter_cs:     %p\n", (void *)guest_area->sysenter_cs);
    V3_Print("sysenter_esp:    %p\n", (void *)guest_area->sysenter_esp);
    V3_Print("sysenter_eip:    %p\n", (void *)guest_area->sysenter_eip);



    /* Other esoteric VMCB Control Fields */
    V3_Print("dbgctl:          %p\n", (void *)guest_area->dbgctl);
    V3_Print("br_from:         %p\n", (void *)guest_area->br_from);
    V3_Print("br_to:           %p\n", (void *)guest_area->br_to);
    V3_Print("lastexcpfrom:    %p\n", (void *)guest_area->lastexcpfrom);
    V3_Print("lastexcpto:      %p\n", (void *)guest_area->lastexcpto);
 
}
