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
    vmcb_seg->selector = seg->selector;
    vmcb_seg->limit    = seg->limit;
    vmcb_seg->base     = seg->base;
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
PrintDebugVMCB(vmcb_t * vmcb) 
{
    vmcb_ctrl_t        * ctrl_area  = GET_VMCB_CTRL_AREA(vmcb);
    vmcb_saved_state_t * guest_area = GET_VMCB_SAVE_STATE_AREA(vmcb);
    reg_ex_t tmp_reg;

    PrintDebug("VMCB (0x%p)\n", (void *)vmcb);

    PrintDebug("--Control Area--\n");
    PrintDebug("CR Reads:  %x\n",  *(uint16_t*)&(ctrl_area->cr_reads));
    PrintDebug("CR Writes: %x\n",  *(uint16_t*)&(ctrl_area->cr_writes));
    PrintDebug("DR Reads:  %x\n",  *(uint16_t*)&(ctrl_area->dr_reads));
    PrintDebug("DR Writes: %x\n",  *(uint16_t*)&(ctrl_area->dr_writes));
  
    PrintDebug("Exception Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->exceptions), 
	        (void   *)&(ctrl_area->exceptions));
    PrintDebug("\tDivide-by-Zero:       %d\n", ctrl_area->exceptions.de);
    PrintDebug("\tDebug:                %d\n", ctrl_area->exceptions.db);
    PrintDebug("\tNMIs                  %d\n", ctrl_area->exceptions.nmi);
    PrintDebug("\tBreakpoint:           %d\n", ctrl_area->exceptions.bp);
    PrintDebug("\tOverflow:             %d\n", ctrl_area->exceptions.of);
    PrintDebug("\tBound-Range:          %d\n", ctrl_area->exceptions.br);
    PrintDebug("\tInvalid Opcode:       %d\n", ctrl_area->exceptions.ud);
    PrintDebug("\tDevice not available: %d\n", ctrl_area->exceptions.nm);
    PrintDebug("\tDouble Fault:         %d\n", ctrl_area->exceptions.df);
    PrintDebug("\tInvalid TSS:          %d\n", ctrl_area->exceptions.ts);
    PrintDebug("\tSegment not present:  %d\n", ctrl_area->exceptions.np);
    PrintDebug("\tStack:                %d\n", ctrl_area->exceptions.ss);
    PrintDebug("\tGPF:                  %d\n", ctrl_area->exceptions.gp);
    PrintDebug("\tPage Fault:           %d\n", ctrl_area->exceptions.pf);
    PrintDebug("\tFloating Point:       %d\n", ctrl_area->exceptions.mf);
    PrintDebug("\tAlignment Check:      %d\n", ctrl_area->exceptions.ac);
    PrintDebug("\tMachine Check:        %d\n", ctrl_area->exceptions.mc);
    PrintDebug("\tSIMD floating point:  %d\n", ctrl_area->exceptions.xf);
    PrintDebug("\tSecurity:             %d\n", ctrl_area->exceptions.sx);

    PrintDebug("Instructions bitmap: %.8x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->instrs), 
	        (void   *)&(ctrl_area->instrs));
    PrintDebug("\tINTR:                 %d\n", ctrl_area->instrs.INTR);
    PrintDebug("\tNMI:                  %d\n", ctrl_area->instrs.NMI);
    PrintDebug("\tSMI:                  %d\n", ctrl_area->instrs.SMI);
    PrintDebug("\tINIT:                 %d\n", ctrl_area->instrs.INIT);
    PrintDebug("\tVINTR:                %d\n", ctrl_area->instrs.VINTR);
    PrintDebug("\tCR0:                  %d\n", ctrl_area->instrs.CR0);
    PrintDebug("\tRD_IDTR:              %d\n", ctrl_area->instrs.RD_IDTR);
    PrintDebug("\tRD_GDTR:              %d\n", ctrl_area->instrs.RD_GDTR);
    PrintDebug("\tRD_LDTR:              %d\n", ctrl_area->instrs.RD_LDTR);
    PrintDebug("\tRD_TR:                %d\n", ctrl_area->instrs.RD_TR);
    PrintDebug("\tWR_IDTR:              %d\n", ctrl_area->instrs.WR_IDTR);
    PrintDebug("\tWR_GDTR:              %d\n", ctrl_area->instrs.WR_GDTR);
    PrintDebug("\tWR_LDTR:              %d\n", ctrl_area->instrs.WR_LDTR);
    PrintDebug("\tWR_TR:                %d\n", ctrl_area->instrs.WR_TR);
    PrintDebug("\tRDTSC:                %d\n", ctrl_area->instrs.RDTSC);
    PrintDebug("\tRDPMC:                %d\n", ctrl_area->instrs.RDPMC);
    PrintDebug("\tPUSHF:                %d\n", ctrl_area->instrs.PUSHF);
    PrintDebug("\tPOPF:                 %d\n", ctrl_area->instrs.POPF);
    PrintDebug("\tCPUID:                %d\n", ctrl_area->instrs.CPUID);
    PrintDebug("\tRSM:                  %d\n", ctrl_area->instrs.RSM);
    PrintDebug("\tIRET:                 %d\n", ctrl_area->instrs.IRET);
    PrintDebug("\tINTn:                 %d\n", ctrl_area->instrs.INTn);
    PrintDebug("\tINVD:                 %d\n", ctrl_area->instrs.INVD);
    PrintDebug("\tPAUSE:                %d\n", ctrl_area->instrs.PAUSE);
    PrintDebug("\tHLT:                  %d\n", ctrl_area->instrs.HLT);
    PrintDebug("\tINVLPG:               %d\n", ctrl_area->instrs.INVLPG);
    PrintDebug("\tINVLPGA:              %d\n", ctrl_area->instrs.INVLPGA);
    PrintDebug("\tIOIO_PROT:            %d\n", ctrl_area->instrs.IOIO_PROT);
    PrintDebug("\tMSR_PROT:             %d\n", ctrl_area->instrs.MSR_PROT);
    PrintDebug("\ttask_switch:          %d\n", ctrl_area->instrs.task_switch);
    PrintDebug("\tFERR_FREEZE:          %d\n", ctrl_area->instrs.FERR_FREEZE);
    PrintDebug("\tshutdown_evts:        %d\n", ctrl_area->instrs.shutdown_evts);

    PrintDebug("SVM Instruction Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->svm_instrs), 
	        (void   *)&(ctrl_area->svm_instrs));
    PrintDebug("\tVMRUN:                %d\n", ctrl_area->svm_instrs.VMRUN);
    PrintDebug("\tVMMCALL:              %d\n", ctrl_area->svm_instrs.VMMCALL);
    PrintDebug("\tVMLOAD:               %d\n", ctrl_area->svm_instrs.VMLOAD);
    PrintDebug("\tVMSAVE:               %d\n", ctrl_area->svm_instrs.VMSAVE);
    PrintDebug("\tSTGI:                 %d\n", ctrl_area->svm_instrs.STGI);
    PrintDebug("\tCLGI:                 %d\n", ctrl_area->svm_instrs.CLGI);
    PrintDebug("\tSKINIT:               %d\n", ctrl_area->svm_instrs.SKINIT);
    PrintDebug("\tRDTSCP:               %d\n", ctrl_area->svm_instrs.RDTSCP);
    PrintDebug("\tICEBP:                %d\n", ctrl_area->svm_instrs.ICEBP);
    PrintDebug("\tWBINVD:               %d\n", ctrl_area->svm_instrs.WBINVD);
    PrintDebug("\tMONITOR:              %d\n", ctrl_area->svm_instrs.MONITOR);
    PrintDebug("\tMWAIT_always:         %d\n", ctrl_area->svm_instrs.MWAIT_always);
    PrintDebug("\tMWAIT_if_armed:       %d\n", ctrl_area->svm_instrs.MWAIT_if_armed);



    PrintDebug("IOPM_BASE_PA:  %p\n",   (void *)ctrl_area->IOPM_BASE_PA);
    PrintDebug("MSRPM_BASE_PA: %p\n",   (void *)ctrl_area->MSRPM_BASE_PA);

    PrintDebug("TSC_OFFSET:    %llu\n", ctrl_area->TSC_OFFSET);

    PrintDebug("guest_ASID:    %d\n",   ctrl_area->guest_ASID);
    PrintDebug("TLB_CONTROL:   %d\n",   ctrl_area->TLB_CONTROL);


    PrintDebug("Guest Control Bitmap: %x (at 0x%p)\n", 
	       *(uint_t *)&(ctrl_area->guest_ctrl), 
	        (void   *)&(ctrl_area->guest_ctrl));
    PrintDebug("\tV_TPR:               %d\n", ctrl_area->guest_ctrl.V_TPR);
    PrintDebug("\tV_IRQ:               %d\n", ctrl_area->guest_ctrl.V_IRQ);
    PrintDebug("\tV_INTR_PRIO:         %d\n", ctrl_area->guest_ctrl.V_INTR_PRIO);
    PrintDebug("\tV_IGN_TPR:           %d\n", ctrl_area->guest_ctrl.V_IGN_TPR);
    PrintDebug("\tV_INTR_MASKING:      %d\n", ctrl_area->guest_ctrl.V_INTR_MASKING);
    PrintDebug("\tV_INTR_VECTOR:       %d\n", ctrl_area->guest_ctrl.V_INTR_VECTOR);

    PrintDebug("Interrupt_shadow: %d\n",    ctrl_area->interrupt_shadow);
    PrintDebug("exit_code:        %llu\n",  ctrl_area->exit_code);
    PrintDebug("exit_info1:       %llu\n",  ctrl_area->exit_info1);
    PrintDebug("exit_info2:       %llu\n",  ctrl_area->exit_info2);


    PrintDebug("Exit Int Info: (at 0x%p)\n", 
	       (void *)&(ctrl_area->exit_int_info));
    PrintDebug("\tVector:     %d\n",  ctrl_area->exit_int_info.vector);
    PrintDebug("\t    (type=%d) (ev=%d) (valid=%d)\n", 
	                              ctrl_area->exit_int_info.type, 
	                              ctrl_area->exit_int_info.ev, 
                                      ctrl_area->exit_int_info.valid);
    PrintDebug("\tError Code: %d\n",  ctrl_area->exit_int_info.error_code);


    PrintDebug("Event Injection: (at 0x%p)\n", 
	       (void *)&(ctrl_area->EVENTINJ));
    PrintDebug("\tVector: %d\n",      ctrl_area->EVENTINJ.vector);
    PrintDebug("\t    (type=%d) (ev=%d) (valid=%d)\n", 
	                              ctrl_area->EVENTINJ.type, 
	                              ctrl_area->EVENTINJ.ev, 
                                      ctrl_area->EVENTINJ.valid);
    PrintDebug("\tError Code: %d\n",  ctrl_area->EVENTINJ.error_code);



    PrintDebug("LBR_VIRTUALIZATION_ENABLE: %d\n", ctrl_area->LBR_VIRTUALIZATION_ENABLE);
    PrintDebug("NP_ENABLE:                 %llu\n", ctrl_area->NP_ENABLE);
    PrintDebug("N_CR3:                     %p\n", (void *)ctrl_area->N_CR3);



    PrintDebug("\n--Guest Saved State--\n");

    PrintDebug("es Selector (at 0x%p): \n", (void *)&(guest_area->es));
    PrintDebug("\tSelector: %d\n",      guest_area->es.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->es.attrib.fields.type, 
                                        guest_area->es.attrib.fields.S, 
	                                guest_area->es.attrib.fields.dpl, 
                                        guest_area->es.attrib.fields.P,
	                                guest_area->es.attrib.fields.avl, 
                                        guest_area->es.attrib.fields.L,
	                                guest_area->es.attrib.fields.db, 
	                                guest_area->es.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->es.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->es.base);


    PrintDebug("cs Selector (at 0x%p): \n", (void *)&(guest_area->cs));
    PrintDebug("\tSelector: %d\n",      guest_area->cs.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->cs.attrib.fields.type, 
	                                guest_area->cs.attrib.fields.S, 
	                                guest_area->cs.attrib.fields.dpl, 
	                                guest_area->cs.attrib.fields.P,
	                                guest_area->cs.attrib.fields.avl,  
	                                guest_area->cs.attrib.fields.L,
	                                guest_area->cs.attrib.fields.db,   
	                                guest_area->cs.attrib.fields.G);
    PrintDebug("\tLimit:    %u\n",      guest_area->cs.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->cs.base);


    PrintDebug("ss Selector (at 0x%p): \n", (void *)&(guest_area->ss));
    PrintDebug("\tSelector: %d\n",      guest_area->ss.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->ss.attrib.fields.type, 
	                                guest_area->ss.attrib.fields.S, 
	                                guest_area->ss.attrib.fields.dpl, 
	                                guest_area->ss.attrib.fields.P,
	                                guest_area->ss.attrib.fields.avl,
	                                guest_area->ss.attrib.fields.L,
	                                guest_area->ss.attrib.fields.db, 
	                                guest_area->ss.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->ss.limit);
    PrintDebug("\tBase:     0x%llu\n",  guest_area->ss.base);


    PrintDebug("ds Selector (at 0x%p): \n", (void *)&(guest_area->ds));
    PrintDebug("\tSelector: %d\n",      guest_area->ds.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->ds.attrib.fields.type,
	                                guest_area->ds.attrib.fields.S, 
	                                guest_area->ds.attrib.fields.dpl, 
	                                guest_area->ds.attrib.fields.P,
	                                guest_area->ds.attrib.fields.avl, 
	                                guest_area->ds.attrib.fields.L,
	                                guest_area->ds.attrib.fields.db, 
	                                guest_area->ds.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->ds.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->ds.base);
 

    PrintDebug("fs Selector (at 0x%p): \n", (void *)&(guest_area->fs));
    PrintDebug("\tSelector: %d\n",      guest_area->fs.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->fs.attrib.fields.type, 
	                                guest_area->fs.attrib.fields.S, 
	                                guest_area->fs.attrib.fields.dpl, 
	                                guest_area->fs.attrib.fields.P,
	                                guest_area->fs.attrib.fields.avl, 
	                                guest_area->fs.attrib.fields.L,
	                                guest_area->fs.attrib.fields.db, 
	                                guest_area->fs.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->fs.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->fs.base);


    PrintDebug("gs Selector (at 0x%p): \n", (void *)&(guest_area->gs));
    PrintDebug("\tSelector: %d\n",      guest_area->gs.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->gs.attrib.fields.type, 
	                                guest_area->gs.attrib.fields.S, 
	                                guest_area->gs.attrib.fields.dpl, 
	                                guest_area->gs.attrib.fields.P,
	                                guest_area->gs.attrib.fields.avl, 
	                                guest_area->gs.attrib.fields.L,
	                                guest_area->gs.attrib.fields.db, 
	                                guest_area->gs.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->gs.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->gs.base);


    PrintDebug("gdtr Selector (at 0x%p): \n", (void *)&(guest_area->gdtr));
    PrintDebug("\tSelector: %d\n",      guest_area->gdtr.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->gdtr.attrib.fields.type, 
	                                guest_area->gdtr.attrib.fields.S, 
	                                guest_area->gdtr.attrib.fields.dpl,
	                                guest_area->gdtr.attrib.fields.P,
	                                guest_area->gdtr.attrib.fields.avl, 
	                                guest_area->gdtr.attrib.fields.L,
	                                guest_area->gdtr.attrib.fields.db, 
	                                guest_area->gdtr.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->gdtr.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->gdtr.base);


    PrintDebug("ldtr Selector (at 0x%p): \n", (void *)&(guest_area->ldtr));
    PrintDebug("\tSelector: %d\n",      guest_area->ldtr.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->ldtr.attrib.fields.type, 
	                                guest_area->ldtr.attrib.fields.S, 
	                                guest_area->ldtr.attrib.fields.dpl, 
	                                guest_area->ldtr.attrib.fields.P,
	                                guest_area->ldtr.attrib.fields.avl, 
	                                guest_area->ldtr.attrib.fields.L,
	                                guest_area->ldtr.attrib.fields.db, 
	                                guest_area->ldtr.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->ldtr.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->ldtr.base);


    PrintDebug("idtr Selector (at 0x%p): \n", &(guest_area->idtr));
    PrintDebug("\tSelector: %d\n",      guest_area->idtr.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->idtr.attrib.fields.type, 
	                                guest_area->idtr.attrib.fields.S, 
	                                guest_area->idtr.attrib.fields.dpl, 
	                                guest_area->idtr.attrib.fields.P,
	                                guest_area->idtr.attrib.fields.avl, 
	                                guest_area->idtr.attrib.fields.L,
	                                guest_area->idtr.attrib.fields.db, 
	                                guest_area->idtr.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->idtr.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->idtr.base);


    PrintDebug("tr Selector (at 0x%p): \n", &(guest_area->tr));
    PrintDebug("\tSelector: %d\n",      guest_area->tr.selector); 
    PrintDebug("\t(type=%x), (S=%d), (dpl=%d), (P=%d), (avl=%d), (L=%d), (db=%d), (G=%d)\n", 
	                                guest_area->tr.attrib.fields.type, 
	                                guest_area->tr.attrib.fields.S, 
	                                guest_area->tr.attrib.fields.dpl, 
	                                guest_area->tr.attrib.fields.P,
	                                guest_area->tr.attrib.fields.avl, 
	                                guest_area->tr.attrib.fields.L,
	                                guest_area->tr.attrib.fields.db, 
	                                guest_area->tr.attrib.fields.G);
    PrintDebug("\tlimit:    %u\n",      guest_area->tr.limit);
    PrintDebug("\tBase:     0x%llx\n",  guest_area->tr.base);


    PrintDebug("cpl:    %d\n", guest_area->cpl);

  
    PrintDebug("RIP:    %p\n", (void *)guest_area->rip);
    PrintDebug("RSP     %p\n", (void *)guest_area->rsp);
    PrintDebug("RFLAGS: %p\n", (void *)guest_area->rflags);
    PrintDebug("EFER:   %p\n", (void *)guest_area->efer);
    PrintDebug("CR0:    %p\n", (void *)guest_area->cr0);
    PrintDebug("CR3:    %p\n", (void *)guest_area->cr3);
    PrintDebug("CR4:    %p\n", (void *)guest_area->cr4);
    PrintDebug("DR7:    %p\n", (void *)guest_area->dr7);
    PrintDebug("DR6:    %p\n", (void *)guest_area->dr6);

  

    PrintDebug("RAX:             %p\n", (void *)guest_area->rax);
    PrintDebug("STAR:            %p\n", (void *)guest_area->star);
    PrintDebug("LSTAR:           %p\n", (void *)guest_area->lstar);
    PrintDebug("CSTAR:           %p\n", (void *)guest_area->cstar);
    PrintDebug("SFMASK:          %p\n", (void *)guest_area->sfmask);
    PrintDebug("KernelGsBase:    %p\n", (void *)guest_area->KernelGsBase);
    PrintDebug("sysenter_cs:     %p\n", (void *)guest_area->sysenter_cs);
    PrintDebug("sysenter_esp:    %p\n", (void *)guest_area->sysenter_esp);
    PrintDebug("sysenter_eip:    %p\n", (void *)guest_area->sysenter_eip);
    PrintDebug("CR2:             %p\n", (void *)guest_area->cr2);



    tmp_reg.r_reg = guest_area->g_pat;
    PrintDebug("g_pat: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
    tmp_reg.r_reg = guest_area->dbgctl;
    PrintDebug("dbgctl: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
    tmp_reg.r_reg = guest_area->br_from;
    PrintDebug("br_from: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
    tmp_reg.r_reg = guest_area->br_to;
    PrintDebug("br_to: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
    tmp_reg.r_reg = guest_area->lastexcpfrom;
    PrintDebug("lastexcpfrom: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
    tmp_reg.r_reg = guest_area->lastexcpto;
    PrintDebug("lastexcpto: hi: 0x%x, lo: 0x%x\n", tmp_reg.e_reg.high, tmp_reg.e_reg.low);
}
