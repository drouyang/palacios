#ifndef _PALACIOS_H
#define _PALACIOS_H

#include <lwk/types.h>
#include <lwk/list.h>
#include <lwk/rbtree.h>
#include <lwk/smp.h>


#include <palacios/vmm.h>
#include <palacios/vmm_host_events.h>

//#include "kitten-exts.h"

/* Global Control IOCTLs */
#define V3_ADD_CPU                1
#define V3_ADD_MEMORY             2
#define V3_ADD_PCI_HW_DEV         5

#define V3_CREATE_GUEST          12
#define V3_FREE_GUEST            13

/* VM Specific IOCTLs */
#define V3_VM_PAUSE              23
#define V3_VM_CONTINUE           24

#define V3_VM_LAUNCH             25
#define V3_VM_STOP               26
#define V3_VM_LOAD               27
#define V3_VM_SAVE               28
#define V3_VM_SIMULATE           29

#define V3_VM_INSPECT            30
#define V3_VM_DEBUG              31

#define V3_VM_MOVE_CORE          33
#define V3_VM_SEND               34
#define V3_VM_RECEIVE            35

#define V3_VM_CONSOLE_CONNECT    40
#define V3_VM_CONSOLE_DISCONNECT 41
#define V3_VM_KEYBOARD_EVENT     42
#define V3_VM_STREAM_CONNECT     45

#define V3_VM_XPMEM_CONNECT      12000

#define V3_CMD_PATH         "/palacios-cmd"
#define V3_VM_PATH          "/palacios-vm"

#define MAX_VMS 32

struct inode;

struct v3_guest {
    void * v3_ctx;

    void * img; 
    u32 img_size;

    char name[128];
    
    struct inode * kfs_inode;

    int guest_id;

    struct rb_root vm_ctrls;
    struct list_head exts;

};

struct v3_hw_pci_dev {
    char name[128];
    unsigned int bus;
    unsigned int dev;
    unsigned int func;
} __attribute__((packed));


struct v3_debug_cmd {
    unsigned int core; 
    unsigned int cmd;
} __attribute__((packed));

struct v3_core_move_cmd {
    unsigned short vcore_id;
    unsigned short pcore_id;
} __attribute__((packed));


/**
 * These are used by the kernel to forward events to Palacios.
 */
extern void send_key_to_palacios(struct v3_guest * guest, unsigned char status, unsigned char scan_code);

int palacios_vmm_init(char * options);










#define v3_lwk_printk(fmt, args...)					\
    do {								\
	printk("V3-lwk> [%s] (%u): " fmt, current->name, get_cpu(), ##args); \
    } while (0)

#define ERROR(fmt, args...)						\
    do {								\
	printk(KERN_ERR "V3-lwk> [%s] (%u) %s(%d): " fmt, current->name, get_cpu(),  __FILE__, __LINE__, ##args); \
    } while (0)

#define WARNING(fmt, args...)						\
    do {								\
	printk(KERN_WARNING "V3-lwk> [%s] (%u): " fmt, current->name, get_cpu(), ##args); \
    } while (0)

#define DEBUG(fmt, args...)						\
    do {								\
	printk(KERN_DEBUG "V3-lwk> [%s] (%u): " fmt, current->name, get_cpu(), ##args); \
    } while (0)

#endif
