/* 
 * Pisces based VM Console 
 * (c) 2013, Jack Lange  (jacklange@cs.pitt.edu)
 */

#include <lwk/list.h>
#include <lwk/spinlock.h>
#include <lwk/kfs.h>
#include <lwk/kernel.h>
#include <lwk/string.h>
#include <lwk/pmem.h>

#include <arch/uaccess.h>
#include <arch/apic.h>


#include <arch/pisces/pisces_lock.h>
#include <arch/pisces/pisces_file.h>

#include <interfaces/vmm_console.h>
#include <palacios/vmm_host_events.h>


#include "palacios.h"
#include "kitten-exts.h"


typedef enum { CONSOLE_CURS_SET = 1,
	       CONSOLE_CHAR_SET = 2,
	       CONSOLE_SCROLL = 3,
	       CONSOLE_UPDATE = 4,
               CONSOLE_RESOLUTION = 5} console_op_t;




struct cursor_msg {
    int x;
    int y;
} __attribute__((packed));

struct character_msg {
    int x;
    int y;
    char c;
    unsigned char style;
} __attribute__((packed));

struct scroll_msg {
    int lines;
} __attribute__((packed));


struct resolution_msg {
    int cols;
    int rows;
} __attribute__((packed));

struct cons_msg {
    unsigned char op;
    union {
	struct cursor_msg     cursor;
	struct character_msg  character;
	struct scroll_msg     scroll;
	struct resolution_msg resolution;
    };
} __attribute__((packed)); 


struct cons_ring_buf {
    struct pisces_spinlock lock;
    u16 read_idx;
    u16 write_idx;
    u16 cur_entries;
    u16 total_entries;
    u16 kick_ipi_vec;
    u16 kick_apic;

    struct cons_msg msgs[0];
} __attribute__((packed));

#define RING_BUF_SIZE (16 * PAGE_SIZE)


struct palacios_console {
    spinlock_t cons_lock;

    int open;
    int connected;
    int active;

    unsigned int width;
    unsigned int height;

    uintptr_t ring_buf_pg_addr;
    struct cons_ring_buf * ring_buf;

    struct v3_guest * guest;
};




static int 
kbd_event(struct v3_guest * guest, 
	  unsigned int      cmd, 
	  unsigned long     arg, 
	  void            * priv_data) 
{
    struct palacios_console * cons  = priv_data;
    struct v3_keyboard_event  event = {0, 0};
    
    if (cons->open == 0) {
	printk("Error: Console not open\n");
	return 0;
    }


    event.scan_code = (u8)arg;

    //printk("Sending scan_code (%x) to VM (%p)\n", event.scan_code, cons->guest->v3_ctx);

    v3_deliver_keyboard_event(cons->guest->v3_ctx, &event);
    
    return 0;
}




static int 
console_connect(struct v3_guest * guest, 
		unsigned int      cmd, 
		unsigned long     arg,
		void            * priv_data)
{
    void __user             * argp = (void __user *)arg;
    struct palacios_console * cons = priv_data;
    
    uintptr_t              ring_buf_pa  = 0;
    struct cons_ring_buf * ring_buf_ptr = NULL;

    struct pmem_region result;
    int                acquired = 0;
    unsigned long      flags    = 0;

    printk("V3: Connecting to VM console\n");

    if (cons->open == 0) {
	printk(KERN_ERR "Attempted to connect to unopened console\n");
	return -1;
    }


    if (pmem_alloc_umem(RING_BUF_SIZE, RING_BUF_SIZE, &result) != 0) {
	printk(KERN_ERR "Error allocating Console Ring Buffer\n");
	return -1;
    }

    if (pmem_zero(&result) != 0) {
	printk(KERN_ERR "Error zeroing console ring buffer\n");
	return -1;
    }

    ring_buf_pa  =      result.start;
    ring_buf_ptr = __va(result.start);

    pisces_lock_init(&(ring_buf_ptr->lock));
    ring_buf_ptr->total_entries = ((RING_BUF_SIZE - sizeof(struct cons_ring_buf)) / sizeof(struct cons_msg));


    spin_lock_irqsave(&(cons->cons_lock), flags);
    {
	if (cons->connected == 0) {
	    cons->ring_buf_pg_addr = ring_buf_pa;
	    cons->ring_buf         = ring_buf_ptr;
	    cons->connected        = 1;
	    acquired               = 1;
	}
    }
    spin_unlock_irqrestore(&(cons->cons_lock), flags);

    if (acquired == 0) {
	int status = 0;

	printk(KERN_ERR "Console already connected\n");

	result.allocated = false;
	status           = pmem_update(&result);
	    
	if (status) {
	    panic("Failed to free page %p! (status=%d)",
		  ring_buf_pa, status);
	}
	
	return -1;
    }


    if (copy_to_user(argp, &(cons->ring_buf_pg_addr), sizeof(u64))) {
	printk("ERROR Copying Console Ring buffer to user space\n");
    }

    v3_deliver_console_event(guest->v3_ctx, NULL);
    printk("Console connected\n");

    return 0;
}

static int 
console_disconnect(struct v3_guest * guest, 
		   unsigned int      cmd, 
		   unsigned long     arg, 
		   void            * priv_data)
{
    struct palacios_console * cons        = priv_data;
    uintptr_t                 ring_buf_pa = cons->ring_buf_pg_addr;
    unsigned long flags;

    spin_lock_irqsave(&(cons->cons_lock), flags);
    {
	cons->connected        = 0;
	cons->ring_buf_pg_addr = 0;
	cons->ring_buf         = NULL;
	
	// Free the ring buffer
	{
	    /* 
	     * OK.... So kitten really needs a pmem_free interface......
	     */
	    struct pmem_region      query;
	    struct pmem_region      result;
	    int                     status;
	    
	    pmem_region_unset_all(&query);
	    
	    query.start             = (uintptr_t) ring_buf_pa;
	    query.end               = (uintptr_t) ring_buf_pa + RING_BUF_SIZE;
	    query.allocated         = true;
	    query.allocated_is_set  = true;
	    
	    status = pmem_query(&query, &result);
	    
	    if (status) {
		panic("Freeing page %p failed! query status=%d",
		      ring_buf_pa, status);
	    }
	    
	    result.allocated = false;
	    
	    status = pmem_update(&result);
	    
	    if (status) {
		panic("Failed to free page %p! (status=%d)",
		      ring_buf_pa, status);
	    }
	}
    }
    spin_unlock_irqrestore(&(cons->cons_lock), flags);

    return 0;
}



static void * palacios_tty_open(void * private_data, unsigned int width, unsigned int height) {
    struct v3_guest * guest = (struct v3_guest *)private_data;
    struct palacios_console * cons = kmem_alloc(sizeof(struct palacios_console));

    if (!cons) { 
	printk(KERN_ERR "Cannot allocate memory for console\n");
	return NULL;
    }

    printk("Guest initialized virtual console (Guest=%s)\n", guest->name);

    if (guest == NULL) {
	printk(KERN_ERR "ERROR: Cannot open a console on a NULL guest\n");
	kmem_free(cons);
	return NULL;
    }

    /*if (cons->open == 1) {
	printk(KERN_ERR "Console already open\n");
	kmem_free(cons);
	return NULL;
    }*/



    spin_lock_init(&(cons->cons_lock));

    cons->guest = guest;

    cons->connected = 0;
    cons->width     = width;
    cons->height    = height;
    cons->open      = 1;


    add_guest_ctrl(guest, V3_VM_CONSOLE_CONNECT,    console_connect,    cons);
    add_guest_ctrl(guest, V3_VM_CONSOLE_DISCONNECT, console_disconnect, cons);
    add_guest_ctrl(guest, V3_VM_KEYBOARD_EVENT,     kbd_event,          cons);
    return cons;
}


static int enqueue(struct palacios_console * cons, struct cons_msg * msg) {
    struct cons_ring_buf * buf = cons->ring_buf;

    pisces_spin_lock(&(buf->lock));

    if (buf->cur_entries >= buf->total_entries) {
	pisces_spin_unlock(&(buf->lock));
	return -1;
    }

    memcpy(&(buf->msgs[buf->write_idx]), msg, sizeof(struct cons_msg));
    
    __asm__ __volatile__ ("lock incw %1;"
			  : "+m"(buf->cur_entries)
			  :
			  : "memory");

    buf->write_idx++;
    buf->write_idx %= buf->total_entries;

    
    pisces_spin_unlock(&(buf->lock));
    
    return 0;
}

static int post_msg(struct palacios_console * cons, struct cons_msg * msg) {
    //    DEBUG("Posting Console message\n");

    if (enqueue(cons, msg) == -1) {
	
	printk("CONSOLE RING BUFFER OVERFLOW\n");
	printk("CONSOLE RING BUFFER OVERFLOW\n");

	if (cons->ring_buf->kick_ipi_vec != 0) {	    
	    lapic_send_ipi_to_apic(cons->ring_buf->kick_apic, cons->ring_buf->kick_ipi_vec);
	} 

	while (enqueue(cons, msg) == -1) {
	    schedule_timeout(2000);

	    if (cons->ring_buf->kick_ipi_vec != 0) {	    
		lapic_send_ipi_to_apic(cons->ring_buf->kick_apic, cons->ring_buf->kick_ipi_vec);
	    } 
	}
    }


    if (cons->ring_buf->kick_ipi_vec != 0) {
	lapic_send_ipi_to_apic(cons->ring_buf->kick_apic, cons->ring_buf->kick_ipi_vec);
	// send IPI
    } 

    return 0;
}


static int palacios_tty_cursor_set(void * console, int x, int y) {
    struct palacios_console * cons = (struct palacios_console *)console;
    struct cons_msg msg;

    if (cons->connected == 0) {
	return 0;
    }

    memset(&msg, 0, sizeof(struct cons_msg));

    msg.op       = CONSOLE_CURS_SET;
    msg.cursor.x = x;
    msg.cursor.y = y;

    return post_msg(cons, &msg);
}

static int palacios_tty_character_set(void * console, int x, int y, char c, unsigned char style) {
    struct palacios_console * cons = (struct palacios_console *) console;
    struct cons_msg msg;

    if (cons->connected == 0) {
	return 0;
    }

    memset(&msg, 0, sizeof(struct cons_msg));

    msg.op              = CONSOLE_CHAR_SET;
    msg.character.x     = x;
    msg.character.y     = y;
    msg.character.c     = c;
    msg.character.style = style;

    return post_msg(cons, &msg);
}

static int palacios_tty_scroll(void * console, int lines) {
    struct palacios_console * cons = (struct palacios_console *) console;
    struct cons_msg msg;

    if (cons->connected == 0) {
	return 0;
    }

    memset(&msg, 0, sizeof(struct cons_msg));

    msg.op = CONSOLE_SCROLL;
    msg.scroll.lines = lines;

    return post_msg(cons, &msg);
}

static int palacios_set_text_resolution(void * console, int cols, int rows) {
    struct palacios_console * cons = (struct palacios_console *)console;
    struct cons_msg msg;

    if (cons->connected == 0) {
	return 0;
    }

    memset(&msg, 0, sizeof(struct cons_msg));

    msg.op = CONSOLE_RESOLUTION;
    msg.resolution.cols = cols;
    msg.resolution.rows = rows;

    return post_msg(cons, &msg);
}

static int palacios_tty_update(void * console) {
    struct palacios_console * cons = (struct palacios_console *) console;
    struct cons_msg msg;

    if (cons->connected == 0) {
	return 0;
    }

    memset(&msg, 0, sizeof(struct cons_msg));

    msg.op = CONSOLE_UPDATE;

    return post_msg(cons, &msg);
}

static void palacios_tty_close(void * console) {
    struct palacios_console * cons = (struct palacios_console *) console;

    cons->open = 0;

    kmem_free(cons);
}



static struct v3_console_hooks palacios_console_hooks = {
    .open			= palacios_tty_open,
    .set_cursor	                = palacios_tty_cursor_set,
    .set_character	        = palacios_tty_character_set,
    .scroll			= palacios_tty_scroll,
    .set_text_resolution        = palacios_set_text_resolution,
    .update			= palacios_tty_update,
    .close                      = palacios_tty_close,
};






static int console_init( void ) {
    V3_Init_Console(&palacios_console_hooks);
    
    return 0;
}




static struct kitten_ext console_ext = {
    .name         = "CONSOLE",
    .init         = console_init,
    .deinit       = NULL,
    .guest_init   = NULL,
    .guest_deinit = NULL
};


register_extension(&console_ext);
