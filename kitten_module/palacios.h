#ifndef _PALACIOS_H
#define _PALACIOS_H

#include <lwk/types.h>
#include <lwk/list.h>
#include <lwk/rbtree.h>

#include <palacios/vmm.h>
#include <palacios/vmm_host_events.h>

//#include "kitten-exts.h"


#define V3_ADD_CPU 1

#define V3_CREATE_GUEST 12
#define V3_FREE_GUEST 13

#define V3_VM_LAUNCH 25
#define V3_VM_STOP 26

#define V3_VM_CONSOLE_CONNECT 30
#define V3_VM_CONSOLE_DISCONNECT 31
#define V3_VM_KEYBOARD_EVENT 32

#define V3_ADD_PCI_HW_DEV 55

#define MAX_VMS 32

struct v3_guest {
    void * v3_ctx;

    void * img; 
    u32 img_size;

    char name[128];


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


/**
 * These are used by the kernel to forward events to Palacios.
 */
extern void send_key_to_palacios(struct v3_guest * guest, unsigned char status, unsigned char scan_code);
extern void send_tick_to_palacios(struct v3_guest * guest, unsigned int period_us);


int palacios_vmm_init(char * options);

#endif
