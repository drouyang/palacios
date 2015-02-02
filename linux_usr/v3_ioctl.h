/* 
 * V3 Control header file 
 * (c) Jack lange, 2010
 */

#ifndef __V3_IOCTL_H__
#define __V3_IOCTL_H__

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


#include "v3_types.h"


#define V3_DEV_FILENAME "/dev/v3vee"
#define V3_VM_FILENAME  "/dev/v3-vm"


static inline char * 
get_vm_dev_path(int vm_id) 
{
    char * dev_path = NULL;
    
    asprintf(&dev_path, "/dev/v3-vm%d", vm_id);

    return dev_path;
}

static inline int
get_vm_id_from_path(char * dev_path)
{
    int vm_id = -1;

    if (sscanf(dev_path, "/dev/v3-vm%d", &vm_id) != 1) {
        return -1;
    }

    return vm_id;
}

struct v3_guest_img {
    u64       size;
    uintptr_t guest_data;
    char      name[128];
} __attribute__((packed));


struct v3_mem_region {
    u64 base_addr;
    u64 num_pages;
} __attribute__((packed));


struct v3_core_move_cmd{
    u16 vcore_id;
    u16 pcore_id;
} __attribute__((packed));


struct v3_debug_cmd {
    u32 core; 
    u32 cmd;
} __attribute__((packed));


#define MAX_CHKPT_STORE_LEN 128
#define MAX_CHKPT_URL_LEN   256

struct v3_chkpt_info {
    char store[MAX_CHKPT_STORE_LEN];
    char url[MAX_CHKPT_URL_LEN];     /* This might need to be bigger... */
} __attribute__((packed));



struct v3_hw_pci_dev {
    char url[128];
    u32  bus;
    u32  dev;
    u32  func;
} __attribute__((packed));


#endif
