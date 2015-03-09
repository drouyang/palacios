#ifndef _PALACIOS_H
#define _PALACIOS_H

#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <linux/proc_fs.h>

/* Global Control IOCTLs */
#define V3_ADD_CPU               100   /* Add a physical CPU for use by Palacios                     */
#define V3_ADD_MEM               101   /* Add a physical memory region to Palacios memory manager    */
#define V3_ADD_PCI               102   /* Add a passthrough PCI device for VM assignment             */

#define V3_REMOVE_CPU            105   /* Remove a physical CPU for use by Palacios                  */
#define V3_REMOVE_MEM            106   /* Remove a physical memory region to Palacios memory manager */
#define V3_REMOVE_PCI            107   /* Remove passthrough PCI device for VM assignment            */

#define V3_CREATE_GUEST          112   /* Create a VM from a configuration image                     */
#define V3_FREE_GUEST            113   /* Free a VM and all of its associated state                  */

/* VM Specific IOCTLs */

#define V3_VM_PAUSE              123   /* Pause a running VMs execution                              */
#define V3_VM_CONTINUE           124   /* Continue a running VMs execution                           */

#define V3_VM_LAUNCH             125   /* Launch a previously created VM                             */
#define V3_VM_STOP               126   /* Stop a running VM                                          */
#define V3_VM_LOAD               127   /* Load a VM's execution state from a checkpoint              */
#define V3_VM_SAVE               128   /* Save a VM's execution state to a checkpoint                */
#define V3_VM_SIMULATE           129   /* Cause a VM to enter simulation mode                        */

#define V3_VM_INSPECT            130   /* Request inspection of a VM's state (OBSOLETE)              */
#define V3_VM_DEBUG              131   /* Send a Debug command to a VM                               */

#define V3_VM_MOVE_CORE          133   /* Migrate a VM's VCPU to another physical CPU                */

#define V3_VM_SEND               134   /* Migration command                                          */
#define V3_VM_RECEIVE            135   /* Migration command                                          */

#define V3_VM_CONSOLE_CONNECT    140   /* Connect to a VM's text mode console                        */
#define V3_VM_CONSOLE_DISCONNECT 141   /* Disconnect from a VM's text mode console                   */
#define V3_VM_KEYBOARD_EVENT     142   /* Send a scan scode to the VM's virtual keyboard             */
#define V3_VM_STREAM_CONNECT     145   /* Connect to a VM's named data stream                        */




#define V3_VM_XPMEM_CONNECT      12000


struct v3_guest_img {
    unsigned long long   size;
    void               * guest_data;
    char                 name[128];
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
    char url[256];
} __attribute__((packed));


struct v3_hw_pci_dev {
    char         name[128];
    unsigned int bus;
    unsigned int dev;
    unsigned int func;
} __attribute__((packed));



struct v3_guest {
    void * v3_ctx;

    void * img; 
    u32    img_size;

    char name[128];


    struct rb_root   vm_ctrls;
    struct list_head exts;

    dev_t       vm_dev; 
    struct cdev cdev;

    struct proc_dir_entry  * vm_proc_dir;
};

#define MAX_VMS 32



int palacios_vmm_init( void );
int palacios_vmm_exit( void );


/* Exported Proc Directory for global VMM state */
extern struct proc_dir_entry * palacios_proc_dir;

/* Exported stubs required by VNET */
void       * palacios_start_kernel_thread(int (*fn)(void * arg), void * arg, char * thread_name);
void         palacios_yield_cpu_timed(unsigned int us);
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
