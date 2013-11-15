#ifndef _PALACIOS_H
#define _PALACIOS_H

#include <lwk/types.h>
#include <lwk/list.h>
//#include <linux/rbtree.h>

#include <palacios/vmm.h>
#include <palacios/vmm_host_events.h>



#define V3_CREATE_GUEST 12
#define V3_FREE_GUEST 13

#define V3_VM_LAUNCH 25
#define V3_VM_STOP 26


#define MAX_VMS 32

struct vm_path {
    char file_name[256];
    char vm_name[128];
} __attribute__((packed));

struct v3_guest {
    void * v3_ctx;

    void * img; 
    u32 img_size;

    char name[128];


    //    struct rb_root vm_ctrls;
    struct list_head exts;

};


/**
 * These are used by the kernel to forward events to Palacios.
 */
extern void send_key_to_palacios(struct v3_guest * guest, unsigned char status, unsigned char scan_code);
extern void send_tick_to_palacios(struct v3_guest * guest, unsigned int period_us);


int palacios_vmm_init(char * options);

#endif
