/* (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> */
/* (c) 2008, The V3VEE Project <http://www.v3vee.org> */

#ifndef __SVM_HANDLER_H
#define __SVM_HANDLER_H

#ifdef __V3VEE__

#include <palacios/svm.h>
#include <palacios/vmcb.h>
#include <palacios/vmm.h>



/******************************************/
/* SVM Intercept Exit Codes               */
/* AMD Arch Vol 3, Appendix C, pg 477-478 */
/******************************************/
#define VMEXIT_CR_READ_MASK 0xfffffff0
#define VMEXIT_CR0_READ   0x00000000
#define VMEXIT_CR1_READ   0x00000001
#define VMEXIT_CR2_READ   0x00000002
#define VMEXIT_CR3_READ   0x00000003
#define VMEXIT_CR4_READ   0x00000004
#define VMEXIT_CR5_READ   0x00000005
#define VMEXIT_CR6_READ   0x00000006
#define VMEXIT_CR7_READ   0x00000007
#define VMEXIT_CR8_READ   0x00000008
#define VMEXIT_CR9_READ   0x00000009
#define VMEXIT_CR10_READ  0x0000000a
#define VMEXIT_CR11_READ  0x0000000b
#define VMEXIT_CR12_READ  0x0000000c
#define VMEXIT_CR13_READ  0x0000000d
#define VMEXIT_CR14_READ  0x0000000e
#define VMEXIT_CR15_READ  0x0000000f

#define VMEXIT_CR_WRITE_MASK 0xffffffe0
#define VMEXIT_CR0_WRITE   0x00000010
#define VMEXIT_CR1_WRITE   0x00000011
#define VMEXIT_CR2_WRITE   0x00000012
#define VMEXIT_CR3_WRITE   0x00000013
#define VMEXIT_CR4_WRITE   0x00000014
#define VMEXIT_CR5_WRITE   0x00000015
#define VMEXIT_CR6_WRITE   0x00000016
#define VMEXIT_CR7_WRITE   0x00000017
#define VMEXIT_CR8_WRITE   0x00000018
#define VMEXIT_CR9_WRITE   0x00000019
#define VMEXIT_CR10_WRITE  0x0000001a
#define VMEXIT_CR11_WRITE  0x0000001b
#define VMEXIT_CR12_WRITE  0x0000001c
#define VMEXIT_CR13_WRITE  0x0000001d
#define VMEXIT_CR14_WRITE  0x0000001e
#define VMEXIT_CR15_WRITE  0x0000001f

#define VMEXIT_DR_READ_MASK 0xffffffd0
#define VMEXIT_DR0_READ   0x00000020
#define VMEXIT_DR1_READ   0x00000021
#define VMEXIT_DR2_READ   0x00000022
#define VMEXIT_DR3_READ   0x00000023
#define VMEXIT_DR4_READ   0x00000024
#define VMEXIT_DR5_READ   0x00000025
#define VMEXIT_DR6_READ   0x00000026
#define VMEXIT_DR7_READ   0x00000027
#define VMEXIT_DR8_READ   0x00000028
#define VMEXIT_DR9_READ   0x00000029
#define VMEXIT_DR10_READ  0x0000002a
#define VMEXIT_DR11_READ  0x0000002b
#define VMEXIT_DR12_READ  0x0000002c
#define VMEXIT_DR13_READ  0x0000002d
#define VMEXIT_DR14_READ  0x0000002e
#define VMEXIT_DR15_READ  0x0000002f

#define VMEXIT_DR_WRITE_MASK     0xffffffc0
#define VMEXIT_DR0_WRITE   0x00000030 // ? this was previously 3f
#define VMEXIT_DR1_WRITE   0x00000031
#define VMEXIT_DR2_WRITE   0x00000032
#define VMEXIT_DR3_WRITE   0x00000033
#define VMEXIT_DR4_WRITE   0x00000034
#define VMEXIT_DR5_WRITE   0x00000035
#define VMEXIT_DR6_WRITE   0x00000036
#define VMEXIT_DR7_WRITE   0x00000037
#define VMEXIT_DR8_WRITE   0x00000038
#define VMEXIT_DR9_WRITE   0x00000039
#define VMEXIT_DR10_WRITE  0x0000003a
#define VMEXIT_DR11_WRITE  0x0000003b
#define VMEXIT_DR12_WRITE  0x0000003c
#define VMEXIT_DR13_WRITE  0x0000003d
#define VMEXIT_DR14_WRITE  0x0000003e
#define VMEXIT_DR15_WRITE  0x0000003f

#define VMEXIT_EXCP_MASK   0xffffffa0
#define VMEXIT_EXCP0       0x00000040
#define VMEXIT_EXCP1       0x00000041
#define VMEXIT_EXCP2       0x00000042
#define VMEXIT_EXCP3       0x00000043
#define VMEXIT_EXCP4       0x00000044
#define VMEXIT_EXCP5       0x00000045
#define VMEXIT_EXCP6       0x00000046
#define VMEXIT_EXCP7       0x00000047
#define VMEXIT_EXCP8       0x00000048
#define VMEXIT_EXCP9       0x00000049
#define VMEXIT_EXCP10      0x0000004a
#define VMEXIT_EXCP11      0x0000004b
#define VMEXIT_EXCP12      0x0000004c
#define VMEXIT_EXCP13      0x0000004d
#define VMEXIT_EXCP14      0x0000004e
#define VMEXIT_EXCP15      0x0000004f
#define VMEXIT_EXCP16      0x00000050
#define VMEXIT_EXCP17      0x00000051
#define VMEXIT_EXCP18      0x00000052
#define VMEXIT_EXCP19      0x00000053
#define VMEXIT_EXCP20      0x00000054
#define VMEXIT_EXCP21      0x00000055
#define VMEXIT_EXCP22      0x00000056
#define VMEXIT_EXCP23      0x00000057
#define VMEXIT_EXCP24      0x00000058
#define VMEXIT_EXCP25      0x00000059
#define VMEXIT_EXCP26      0x0000005a
#define VMEXIT_EXCP27      0x0000005b
#define VMEXIT_EXCP28      0x0000005c
#define VMEXIT_EXCP29      0x0000005d
#define VMEXIT_EXCP30      0x0000005e
#define VMEXIT_EXCP31      0x0000005f


#define VMEXIT_INTR                 0x00000060
#define VMEXIT_NMI                  0x00000061
#define VMEXIT_SMI                  0x00000062
#define VMEXIT_INIT                 0x00000063
#define VMEXIT_VINITR               0x00000064
#define VMEXIT_CR0_SEL_WRITE        0x00000065
#define VMEXIT_IDTR_READ            0x00000066
#define VMEXIT_GDTR_READ            0x00000067
#define VMEXIT_LDTR_READ            0x00000068
#define VMEXIT_TR_READ              0x00000069
#define VMEXIT_IDTR_WRITE           0x0000006a
#define VMEXIT_GDTR_WRITE           0x0000006b
#define VMEXIT_LDTR_WRITE           0x0000006c
#define VMEXIT_TR_WRITE             0x0000006d
#define VMEXIT_RDTSC                0x0000006e
#define VMEXIT_RDPMC                0x0000006f
#define VMEXIT_PUSHF                0x00000070
#define VMEXIT_POPF                 0x00000071
#define VMEXIT_CPUID                0x00000072
#define VMEXIT_RSM                  0x00000073
#define VMEXIT_IRET                 0x00000074
#define VMEXIT_SWINT                0x00000075
#define VMEXIT_INVD                 0x00000076
#define VMEXIT_PAUSE                0x00000077
#define VMEXIT_HLT                  0x00000078
#define VMEXIT_INVLPG               0x00000079
#define VMEXIT_INVLPGA              0x0000007a
#define VMEXIT_IOIO                 0x0000007b
#define VMEXIT_MSR                  0x0000007c
#define VMEXIT_TASK_SWITCH          0x0000007d
#define VMEXIT_FERR_FREEZE          0x0000007e
#define VMEXIT_SHUTDOWN             0x0000007f
#define VMEXIT_VMRUN                0x00000080
#define VMEXIT_VMMCALL              0x00000081
#define VMEXIT_VMLOAD               0x00000082
#define VMEXIT_VMSAVE               0x00000083
#define VMEXIT_STGI                 0x00000084
#define VMEXIT_CLGI                 0x00000085
#define VMEXIT_SKINIT               0x00000086
#define VMEXIT_RDTSCP               0x00000087
#define VMEXIT_ICEBP                0x00000088
#define VMEXIT_WBINVD               0x00000089
#define VMEXIT_MONITOR              0x0000008a
#define VMEXIT_MWAIT                0x0000008b
#define VMEXIT_MWAIT_CONDITIONAL    0x0000008c

#define VMEXIT_NPF                  0x00000400

#define VMEXIT_INVALID_VMCB         -1

/******************************************/




static const uchar_t VMEXIT_CR0_READ_STR[] = "VMEXIT_CR0_READ";
static const uchar_t VMEXIT_CR1_READ_STR[] = "VMEXIT_CR1_READ";
static const uchar_t VMEXIT_CR2_READ_STR[] = "VMEXIT_CR2_READ";
static const uchar_t VMEXIT_CR3_READ_STR[] = "VMEXIT_CR3_READ";
static const uchar_t VMEXIT_CR4_READ_STR[] = "VMEXIT_CR4_READ";
static const uchar_t VMEXIT_CR5_READ_STR[] = "VMEXIT_CR5_READ";
static const uchar_t VMEXIT_CR6_READ_STR[] = "VMEXIT_CR6_READ";
static const uchar_t VMEXIT_CR7_READ_STR[] = "VMEXIT_CR7_READ";
static const uchar_t VMEXIT_CR8_READ_STR[] = "VMEXIT_CR8_READ";
static const uchar_t VMEXIT_CR9_READ_STR[] = "VMEXIT_CR9_READ";
static const uchar_t VMEXIT_CR10_READ_STR[] = "VMEXIT_CR10_READ";
static const uchar_t VMEXIT_CR11_READ_STR[] = "VMEXIT_CR11_READ";
static const uchar_t VMEXIT_CR12_READ_STR[] = "VMEXIT_CR12_READ";
static const uchar_t VMEXIT_CR13_READ_STR[] = "VMEXIT_CR13_READ";
static const uchar_t VMEXIT_CR14_READ_STR[] = "VMEXIT_CR14_READ";
static const uchar_t VMEXIT_CR15_READ_STR[] = "VMEXIT_CR15_READ";
static const uchar_t VMEXIT_CR0_WRITE_STR[] = "VMEXIT_CR0_WRITE";
static const uchar_t VMEXIT_CR1_WRITE_STR[] = "VMEXIT_CR1_WRITE";
static const uchar_t VMEXIT_CR2_WRITE_STR[] = "VMEXIT_CR2_WRITE";
static const uchar_t VMEXIT_CR3_WRITE_STR[] = "VMEXIT_CR3_WRITE";
static const uchar_t VMEXIT_CR4_WRITE_STR[] = "VMEXIT_CR4_WRITE";
static const uchar_t VMEXIT_CR5_WRITE_STR[] = "VMEXIT_CR5_WRITE";
static const uchar_t VMEXIT_CR6_WRITE_STR[] = "VMEXIT_CR6_WRITE";
static const uchar_t VMEXIT_CR7_WRITE_STR[] = "VMEXIT_CR7_WRITE";
static const uchar_t VMEXIT_CR8_WRITE_STR[] = "VMEXIT_CR8_WRITE";
static const uchar_t VMEXIT_CR9_WRITE_STR[] = "VMEXIT_CR9_WRITE";
static const uchar_t VMEXIT_CR10_WRITE_STR[] = "VMEXIT_CR10_WRITE";
static const uchar_t VMEXIT_CR11_WRITE_STR[] = "VMEXIT_CR11_WRITE";
static const uchar_t VMEXIT_CR12_WRITE_STR[] = "VMEXIT_CR12_WRITE";
static const uchar_t VMEXIT_CR13_WRITE_STR[] = "VMEXIT_CR13_WRITE";
static const uchar_t VMEXIT_CR14_WRITE_STR[] = "VMEXIT_CR14_WRITE";
static const uchar_t VMEXIT_CR15_WRITE_STR[] = "VMEXIT_CR15_WRITE";
static const uchar_t VMEXIT_DR0_READ_STR[] = "VMEXIT_DR0_READ";
static const uchar_t VMEXIT_DR1_READ_STR[] = "VMEXIT_DR1_READ";
static const uchar_t VMEXIT_DR2_READ_STR[] = "VMEXIT_DR2_READ";
static const uchar_t VMEXIT_DR3_READ_STR[] = "VMEXIT_DR3_READ";
static const uchar_t VMEXIT_DR4_READ_STR[] = "VMEXIT_DR4_READ";
static const uchar_t VMEXIT_DR5_READ_STR[] = "VMEXIT_DR5_READ";
static const uchar_t VMEXIT_DR6_READ_STR[] = "VMEXIT_DR6_READ";
static const uchar_t VMEXIT_DR7_READ_STR[] = "VMEXIT_DR7_READ";
static const uchar_t VMEXIT_DR8_READ_STR[] = "VMEXIT_DR8_READ";
static const uchar_t VMEXIT_DR9_READ_STR[] = "VMEXIT_DR9_READ";
static const uchar_t VMEXIT_DR10_READ_STR[] = "VMEXIT_DR10_READ";
static const uchar_t VMEXIT_DR11_READ_STR[] = "VMEXIT_DR11_READ";
static const uchar_t VMEXIT_DR12_READ_STR[] = "VMEXIT_DR12_READ";
static const uchar_t VMEXIT_DR13_READ_STR[] = "VMEXIT_DR13_READ";
static const uchar_t VMEXIT_DR14_READ_STR[] = "VMEXIT_DR14_READ";
static const uchar_t VMEXIT_DR15_READ_STR[] = "VMEXIT_DR15_READ";
static const uchar_t VMEXIT_DR0_WRITE_STR[] = "VMEXIT_DR0_WRITE";
static const uchar_t VMEXIT_DR1_WRITE_STR[] = "VMEXIT_DR1_WRITE";
static const uchar_t VMEXIT_DR2_WRITE_STR[] = "VMEXIT_DR2_WRITE";
static const uchar_t VMEXIT_DR3_WRITE_STR[] = "VMEXIT_DR3_WRITE";
static const uchar_t VMEXIT_DR4_WRITE_STR[] = "VMEXIT_DR4_WRITE";
static const uchar_t VMEXIT_DR5_WRITE_STR[] = "VMEXIT_DR5_WRITE";
static const uchar_t VMEXIT_DR6_WRITE_STR[] = "VMEXIT_DR6_WRITE";
static const uchar_t VMEXIT_DR7_WRITE_STR[] = "VMEXIT_DR7_WRITE";
static const uchar_t VMEXIT_DR8_WRITE_STR[] = "VMEXIT_DR8_WRITE";
static const uchar_t VMEXIT_DR9_WRITE_STR[] = "VMEXIT_DR9_WRITE";
static const uchar_t VMEXIT_DR10_WRITE_STR[] = "VMEXIT_DR10_WRITE";
static const uchar_t VMEXIT_DR11_WRITE_STR[] = "VMEXIT_DR11_WRITE";
static const uchar_t VMEXIT_DR12_WRITE_STR[] = "VMEXIT_DR12_WRITE";
static const uchar_t VMEXIT_DR13_WRITE_STR[] = "VMEXIT_DR13_WRITE";
static const uchar_t VMEXIT_DR14_WRITE_STR[] = "VMEXIT_DR14_WRITE";
static const uchar_t VMEXIT_DR15_WRITE_STR[] = "VMEXIT_DR15_WRITE";
static const uchar_t VMEXIT_EXCP0_STR[] = "VMEXIT_EXCP0";
static const uchar_t VMEXIT_EXCP1_STR[] = "VMEXIT_EXCP1";
static const uchar_t VMEXIT_EXCP2_STR[] = "VMEXIT_EXCP2";
static const uchar_t VMEXIT_EXCP3_STR[] = "VMEXIT_EXCP3";
static const uchar_t VMEXIT_EXCP4_STR[] = "VMEXIT_EXCP4";
static const uchar_t VMEXIT_EXCP5_STR[] = "VMEXIT_EXCP5";
static const uchar_t VMEXIT_EXCP6_STR[] = "VMEXIT_EXCP6";
static const uchar_t VMEXIT_EXCP7_STR[] = "VMEXIT_EXCP7";
static const uchar_t VMEXIT_EXCP8_STR[] = "VMEXIT_EXCP8";
static const uchar_t VMEXIT_EXCP9_STR[] = "VMEXIT_EXCP9";
static const uchar_t VMEXIT_EXCP10_STR[] = "VMEXIT_EXCP10";
static const uchar_t VMEXIT_EXCP11_STR[] = "VMEXIT_EXCP11";
static const uchar_t VMEXIT_EXCP12_STR[] = "VMEXIT_EXCP12";
static const uchar_t VMEXIT_EXCP13_STR[] = "VMEXIT_EXCP13";
static const uchar_t VMEXIT_EXCP14_STR[] = "VMEXIT_EXCP14";
static const uchar_t VMEXIT_EXCP15_STR[] = "VMEXIT_EXCP15";
static const uchar_t VMEXIT_EXCP16_STR[] = "VMEXIT_EXCP16";
static const uchar_t VMEXIT_EXCP17_STR[] = "VMEXIT_EXCP17";
static const uchar_t VMEXIT_EXCP18_STR[] = "VMEXIT_EXCP18";
static const uchar_t VMEXIT_EXCP19_STR[] = "VMEXIT_EXCP19";
static const uchar_t VMEXIT_EXCP20_STR[] = "VMEXIT_EXCP20";
static const uchar_t VMEXIT_EXCP21_STR[] = "VMEXIT_EXCP21";
static const uchar_t VMEXIT_EXCP22_STR[] = "VMEXIT_EXCP22";
static const uchar_t VMEXIT_EXCP23_STR[] = "VMEXIT_EXCP23";
static const uchar_t VMEXIT_EXCP24_STR[] = "VMEXIT_EXCP24";
static const uchar_t VMEXIT_EXCP25_STR[] = "VMEXIT_EXCP25";
static const uchar_t VMEXIT_EXCP26_STR[] = "VMEXIT_EXCP26";
static const uchar_t VMEXIT_EXCP27_STR[] = "VMEXIT_EXCP27";
static const uchar_t VMEXIT_EXCP28_STR[] = "VMEXIT_EXCP28";
static const uchar_t VMEXIT_EXCP29_STR[] = "VMEXIT_EXCP29";
static const uchar_t VMEXIT_EXCP30_STR[] = "VMEXIT_EXCP30";
static const uchar_t VMEXIT_EXCP31_STR[] = "VMEXIT_EXCP31";
static const uchar_t VMEXIT_INTR_STR[] = "VMEXIT_INTR";
static const uchar_t VMEXIT_NMI_STR[] = "VMEXIT_NMI";
static const uchar_t VMEXIT_SMI_STR[] = "VMEXIT_SMI";
static const uchar_t VMEXIT_INIT_STR[] = "VMEXIT_INIT";
static const uchar_t VMEXIT_VINITR_STR[] = "VMEXIT_VINITR";
static const uchar_t VMEXIT_CR0_SEL_WRITE_STR[] = "VMEXIT_CR0_SEL_WRITE";
static const uchar_t VMEXIT_IDTR_READ_STR[] = "VMEXIT_IDTR_READ";
static const uchar_t VMEXIT_GDTR_READ_STR[] = "VMEXIT_GDTR_READ";
static const uchar_t VMEXIT_LDTR_READ_STR[] = "VMEXIT_LDTR_READ";
static const uchar_t VMEXIT_TR_READ_STR[] = "VMEXIT_TR_READ";
static const uchar_t VMEXIT_IDTR_WRITE_STR[] = "VMEXIT_IDTR_WRITE";
static const uchar_t VMEXIT_GDTR_WRITE_STR[] = "VMEXIT_GDTR_WRITE";
static const uchar_t VMEXIT_LDTR_WRITE_STR[] = "VMEXIT_LDTR_WRITE";
static const uchar_t VMEXIT_TR_WRITE_STR[] = "VMEXIT_TR_WRITE";
static const uchar_t VMEXIT_RDTSC_STR[] = "VMEXIT_RDTSC";
static const uchar_t VMEXIT_RDPMC_STR[] = "VMEXIT_RDPMC";
static const uchar_t VMEXIT_PUSHF_STR[] = "VMEXIT_PUSHF";
static const uchar_t VMEXIT_POPF_STR[] = "VMEXIT_POPF";
static const uchar_t VMEXIT_CPUID_STR[] = "VMEXIT_CPUID";
static const uchar_t VMEXIT_RSM_STR[] = "VMEXIT_RSM";
static const uchar_t VMEXIT_IRET_STR[] = "VMEXIT_IRET";
static const uchar_t VMEXIT_SWINT_STR[] = "VMEXIT_SWINT";
static const uchar_t VMEXIT_INVD_STR[] = "VMEXIT_INVD";
static const uchar_t VMEXIT_PAUSE_STR[] = "VMEXIT_PAUSE";
static const uchar_t VMEXIT_HLT_STR[] = "VMEXIT_HLT";
static const uchar_t VMEXIT_INVLPG_STR[] = "VMEXIT_INVLPG";
static const uchar_t VMEXIT_INVLPGA_STR[] = "VMEXIT_INVLPGA";
static const uchar_t VMEXIT_IOIO_STR[] = "VMEXIT_IOIO";
static const uchar_t VMEXIT_MSR_STR[] = "VMEXIT_MSR";
static const uchar_t VMEXIT_TASK_SWITCH_STR[] = "VMEXIT_TASK_SWITCH";
static const uchar_t VMEXIT_FERR_FREEZE_STR[] = "VMEXIT_FERR_FREEZE";
static const uchar_t VMEXIT_SHUTDOWN_STR[] = "VMEXIT_SHUTDOWN";
static const uchar_t VMEXIT_VMRUN_STR[] = "VMEXIT_VMRUN";
static const uchar_t VMEXIT_VMMCALL_STR[] = "VMEXIT_VMMCALL";
static const uchar_t VMEXIT_VMLOAD_STR[] = "VMEXIT_VMLOAD";
static const uchar_t VMEXIT_VMSAVE_STR[] = "VMEXIT_VMSAVE";
static const uchar_t VMEXIT_STGI_STR[] = "VMEXIT_STGI";
static const uchar_t VMEXIT_CLGI_STR[] = "VMEXIT_CLGI";
static const uchar_t VMEXIT_SKINIT_STR[] = "VMEXIT_SKINIT";
static const uchar_t VMEXIT_RDTSCP_STR[] = "VMEXIT_RDTSCP";
static const uchar_t VMEXIT_ICEBP_STR[] = "VMEXIT_ICEBP";
static const uchar_t VMEXIT_WBINVD_STR[] = "VMEXIT_WBINVD";
static const uchar_t VMEXIT_MONITOR_STR[] = "VMEXIT_MONITOR";
static const uchar_t VMEXIT_MWAIT_STR[] = "VMEXIT_MWAIT";
static const uchar_t VMEXIT_MWAIT_CONDITIONAL_STR[] = "VMEXIT_MWAIT_CONDITIONAL";
static const uchar_t VMEXIT_NPF_STR[] = "VMEXIT_NPF";
static const uchar_t VMEXIT_INVALID_VMCB_STR[] = "VMEXIT_INVALID_VMCB";


const uchar_t * vmexit_code_to_str(uint_t exit_code);



int handle_shadow_paging(struct guest_info * info);

int handle_svm_intr(struct guest_info * info);

int handle_svm_exit(struct guest_info * info);

#endif // ! __V3VEE__

#endif
