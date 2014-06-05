/* 
 * V3 Control header file 
 * (c) Jack lange, 2010
 */

#ifndef _v3_ctrl_h
#define _v3_ctrl_h

#define V3_ADD_CPU               100
#define V3_ADD_MEM               101
#define V3_ADD_PCI               102

#define V3_REMOVE_CPU            105
#define V3_REMOVE_MEM            106
#define V3_REMOVE_PCI            107

#define V3_CREATE_GUEST          112
#define V3_FREE_GUEST            113

/* VM Specific IOCTLs */
#define V3_VM_PAUSE              123
#define V3_VM_CONTINUE           124

#define V3_VM_LAUNCH             125
#define V3_VM_STOP               126
#define V3_VM_LOAD               127
#define V3_VM_SAVE               128
#define V3_VM_SIMULATE           129

#define V3_VM_INSPECT            130
#define V3_VM_DEBUG              131

#define V3_VM_MOVE_CORE          133

#define V3_VM_SEND               134
#define V3_VM_RECEIVE            135

#define V3_VM_CONSOLE_CONNECT    140
#define V3_VM_CONSOLE_DISCONNECT 141
#define V3_VM_KEYBOARD_EVENT     142
#define V3_VM_STREAM_CONNECT     145




#define V3_VM_XPMEM_CONNECT      12000



static const char * v3_dev = "/dev/v3vee";

struct v3_guest_img {
    unsigned long long size;
    void * guest_data;
    char name[128];
} __attribute__((packed));


struct v3_mem_region {
    unsigned long long base_addr;
    unsigned long long num_pages;
} __attribute__((packed));


struct v3_core_move_cmd{
    unsigned short vcore_id;
    unsigned short pcore_id;
} __attribute__((packed));


struct v3_debug_cmd {
    unsigned int core; 
    unsigned int cmd;
} __attribute__((packed));

struct v3_chkpt_info {
    char store[128];
    char url[256]; /* This might need to be bigger... */
} __attribute__((packed));



struct v3_hw_pci_dev {
    char url[128];
    unsigned int bus;
    unsigned int dev;
    unsigned int func;
} __attribute__((packed));


#endif
