/* Palacios/Pisces file interface 
 * (c) Jack Lange, 2013
 */

#include <arch/pisces/pisces_file.h>
#include <lwk/list.h>
#include <lwk/spinlock.h>
#include <lwk/blkdev.h>

#include "palacios.h"
#include "kitten-exts.h"
#include <interfaces/vmm_file.h>

static struct list_head global_files;

#define isprint(a) ((a >= ' ') && (a <= '~'))

struct palacios_file {
    u64 file_handle;

    char * path;
    int    mode;
    
    u8     is_raw_block;
    
    spinlock_t lock;

    struct v3_guest * guest;

    struct list_head file_node;
};


// Currently this just holds the list of open files
struct vm_file_state {
    struct list_head open_files;
};



static int palacios_file_mkdir(const char * pathname, unsigned short perms, int recurse);

/* static int mkdir_recursive(const char * path, unsigned short perms) { */
/*     return -1; */
/* } */

static int 
palacios_file_mkdir(const char    * pathname,
		    unsigned short  perms, 
		    int             recurse) 
{
    return -1;
}

static void * 
palacios_file_open(const char * path, 
		   u64          mode, 
		   void       * private_data) 
{
    struct v3_guest      * guest    = (struct v3_guest *)private_data;
    struct palacios_file * pfile    = NULL;	
    struct vm_file_state * vm_state = NULL;

    if (guest != NULL) {
	vm_state = get_vm_ext_data(guest, "FILE_INTERFACE");
	
	if (vm_state == NULL) {
	    printk(KERN_ERR "ERROR: Could not locate vm file state for extension FILE_INTERFACE\n");
	    return NULL;
	}
    }
    
    pfile = kmem_alloc(sizeof(struct palacios_file));

    if (!pfile) { 
	printk(KERN_ERR "Cannot allocate in file open\n");
	return NULL;
    }

    memset(pfile, 0, sizeof(struct palacios_file));


    pfile->path = kmem_alloc(strlen(path));
    
    if (!pfile->path) { 
	printk(KERN_ERR "Cannot allocate in file open\n");
	kmem_free(pfile);
	return NULL;
    }
    strncpy(pfile->path, path, strlen(path));
    pfile->guest = guest;
    
    spin_lock_init(&(pfile->lock));


    if (mode & FILE_OPEN_MODE_RAW_BLOCK) { 
	blkdev_handle_t blkdev = 0;

	pfile->is_raw_block = 1;

	blkdev = get_blkdev(pfile->path);

	if (blkdev == 0) {
	    printk(KERN_ERR "Could not open Raw Block Device (%s)\n", path);
	    kmem_free(pfile);
	    return NULL;
	}
    } else {

	if ((mode & FILE_OPEN_MODE_READ) && (mode & FILE_OPEN_MODE_WRITE)) { 
	    pfile->mode = O_RDWR;
	} else if (mode & FILE_OPEN_MODE_READ) { 
	    pfile->mode = O_RDONLY;
	} else if (mode & FILE_OPEN_MODE_WRITE) { 
	    pfile->mode = O_WRONLY;
	} 
	
	if (mode & FILE_OPEN_MODE_CREATE) {
	    pfile->mode |= O_CREAT;
	}

	pfile->file_handle = pisces_file_open(path, pfile->mode);
	
	if (pfile->file_handle == 0) {
	    printk(KERN_ERR "Could not open file %s\n", path);
	    kmem_free(pfile);
	    return NULL;
	}
    }

    if (guest == NULL) {
	list_add(&(pfile->file_node), &(global_files));
    } else {
	list_add(&(pfile->file_node), &(vm_state->open_files));
    } 


    return pfile;
}

static int 
palacios_file_close(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    pisces_file_close(pfile->file_handle);
    
    list_del(&(pfile->file_node));

    kmem_free(pfile->path);    
    kmem_free(pfile);

    return 0;
}

static unsigned long long 
palacios_file_size(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    return pisces_file_size(pfile->file_handle);
}

static unsigned long long 
palacios_file_read(void               * file_ptr, 
		   void               * buffer, 
		   unsigned long long   length, 
		   unsigned long long   offset)
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
   
    return pisces_file_read(pfile->file_handle, buffer, length, offset);
}


static unsigned long long 
palacios_file_write(void               * file_ptr, 
		    void               * buffer,
		    unsigned long long   length, 
		    unsigned long long   offset) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    return pisces_file_write(pfile->file_handle, buffer, length, offset);
}

static unsigned long long 
palacios_file_readv(void               * file_ptr,
		    v3_iov_t           * iov_arr, 
		    unsigned int         iov_len,
		    unsigned long long   offset)
{
    struct palacios_file * pfile  = (struct palacios_file *)file_ptr;
    unsigned long long     length = 0;
    int i = 0;

    for (i = 0; i < iov_len; i++) {
	length += pisces_file_read(pfile->file_handle, iov_arr[i].iov_base, iov_arr[i].iov_len, offset + length);
    }

    return length;
}


static unsigned long long 
palacios_file_writev(void               * file_ptr,
		     v3_iov_t           * iov_arr, 
		     unsigned int         iov_len,
		     unsigned long long   offset) 
{
    struct palacios_file * pfile  = (struct palacios_file *)file_ptr;
    unsigned long long     length = 0;
    int i = 0;

    for (i = 0; i < iov_len; i++) {
	length += pisces_file_write(pfile->file_handle, iov_arr[i].iov_base, iov_arr[i].iov_len, offset + length);
    }

    return length;

}


static struct v3_file_hooks palacios_file_hooks = {
	.open		= palacios_file_open,
	.close		= palacios_file_close,
	.read		= palacios_file_read,
	.write		= palacios_file_write,
	.readv          = palacios_file_readv,
	.writev         = palacios_file_writev,
	.size		= palacios_file_size,
	.mkdir          = palacios_file_mkdir,
};



static int file_init( void ) {
    INIT_LIST_HEAD(&(global_files));

    V3_Init_File(&palacios_file_hooks);

    return 0;
}


static int file_deinit( void ) {
    struct palacios_file * pfile = NULL;
    struct palacios_file * tmp = NULL;
    
    list_for_each_entry_safe(pfile, tmp, &(global_files), file_node) { 

        list_del(&(pfile->file_node));
	kmem_free(pfile->path);    
        kmem_free(pfile);
    }

    return 0;
}

static int guest_file_init(struct v3_guest * guest, void ** vm_data) {
    struct vm_file_state * state = kmem_alloc(sizeof(struct vm_file_state));

    if (!state) {
	printk(KERN_ERR "Cannot allocate when intializing file services for guest\n");
	return -1;
    }
	
    
    INIT_LIST_HEAD(&(state->open_files));

    *vm_data = state;


    return 0;
}


static int guest_file_deinit(struct v3_guest * guest, void * vm_data) {
    struct vm_file_state * state = (struct vm_file_state *)vm_data;
    struct palacios_file * pfile = NULL;
    struct palacios_file * tmp = NULL;
    
    list_for_each_entry_safe(pfile, tmp, &(state->open_files), file_node) { 
        list_del(&(pfile->file_node));
        kmem_free(pfile->path);    
        kmem_free(pfile);
    }

    kmem_free(state);
    return 0;
}


static struct kitten_ext file_ext = {
    .name = "FILE_INTERFACE",
    .init = file_init, 
    .deinit = file_deinit,
    .guest_init = guest_file_init,
    .guest_deinit = guest_file_deinit
};

register_extension(&file_ext);
