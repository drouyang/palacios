#ifndef _PALACIOS_H
#define _PALACIOS_H

#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <linux/proc_fs.h>

/* Global Control IOCTLs */
#define V3_ADD_CPU               1
#define V3_ADD_MEMORY            2
#define V3_ADD_PCI_HW_DEV        5

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




#define V3_VM_XPMEM_CONNECT 12000


struct v3_guest_img {
    unsigned long long size;
    void * guest_data;
    char name[128];
} __attribute__((packed));

struct v3_mem_region {
    unsigned long long base_addr;
    unsigned long long num_pages;
} __attribute__((packed));


struct v3_debug_cmd {
    unsigned int core; 
    unsigned int cmd;
} __attribute__((packed));

struct v3_core_move_cmd {
    unsigned short vcore_id;
    unsigned short pcore_id;
} __attribute__((packed));

struct v3_chkpt_info {
    char store[128];
    char url[256]; /* This might need to be bigger... */
} __attribute__((packed));


struct v3_hw_pci_dev {
    char name[128];
    unsigned int bus;
    unsigned int dev;
    unsigned int func;
} __attribute__((packed));



void * trace_malloc(size_t size, gfp_t flags);
void trace_free(const void * objp);


struct v3_guest {
    void * v3_ctx;

    void * img; 
    u32 img_size;

    char name[128];


    struct rb_root vm_ctrls;
    struct list_head exts;

    dev_t vm_dev; 
    struct cdev cdev;
};

// For now MAX_VMS must be a multiple of 8
// This is due to the minor number bitmap
#define MAX_VMS 32



int palacios_vmm_init( void );
int palacios_vmm_exit( void );


// This is how a component finds the proc dir we are using for global state
extern struct proc_dir_entry * palacios_proc_dir;

// Selected exported stubs, for use in other palacios components, like vnet
// The idea is that everything uses the same stubs
void *palacios_start_kernel_thread(int (*fn)(void * arg), void *arg, char *thread_name);
void *palacios_start_thread_on_cpu(int cpu_id, int (*fn)(void * arg), void *arg, char *thread_name);
int   palacios_move_thread_to_cpu(int new_cpu_id, void *thread_ptr);
void palacios_yield_cpu_timed(unsigned int us);
unsigned int palacios_get_cpu(void);



// The following macros are for printing in the linux module
#define v3_lnx_printk(fmt, args...)					\
    do {								\
	task_lock(current);						\
	printk("V3-lnx> [%s] (%u): " fmt, current->comm, palacios_get_cpu(), ##args); \
	task_unlock(current);						\
    } while (0)

#define ERROR(fmt, args...)						\
    do {								\
	task_lock(current);						\
	printk(KERN_ERR "V3-lnx> [%s] (%u) %s(%d): " fmt, current->comm, palacios_get_cpu(),  __FILE__, __LINE__, ##args); \
	task_unlock(current);						\
    } while (0)

#define WARNING(fmt, args...)						\
    do {								\
	task_lock(current);						\
	printk(KERN_WARNING "V3-lnx> [%s] (%u): " fmt, current->comm, palacios_get_cpu(), ##args); \
	task_unlock(current);						\
    } while (0)

#define DEBUG(fmt, args...)						\
    do {								\
	task_lock(current);						\
	printk(KERN_DEBUG "V3-lnx> [%s] (%u): " fmt, current->comm, palacios_get_cpu(), ##args); \
	task_unlock(current);						\
    } while (0)


#endif
