/* Palacios/Pisces file interface 
 * (c) Jack Lange, 2013
 */

#include <arch/pisces/pisces_file.h>
#include <lwk/list.h>
#include <lwk/blkdev.h>

#include "palacios.h"
#include "kitten-exts.h"
#include <interfaces/vmm_file.h>

#define isprint(a) ((a >= ' ') && (a <= '~'))

struct palacios_file {
    uintptr_t file_handle;

    char * path;
    int    mode;
    
    u8     is_raw_block;
    
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
		   int          mode) 
{
    struct palacios_file * pfile    = NULL;	

    
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
    


    if (mode & FILE_OPEN_MODE_RAW_BLOCK) { 
	blkdev_handle_t blkdev = 0;

	pfile->is_raw_block = 1;

	blkdev = get_blkdev(pfile->path);

	if (blkdev == 0) {
	    printk(KERN_ERR "Could not open Raw Block Device (%s)\n", path);
	    kmem_free(pfile);
	    return NULL;
	}

	pfile->file_handle = (uintptr_t)blkdev;
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


    return pfile;
}

static int 
palacios_file_close(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    if (pfile == NULL) {
        return -1;
    }

    if (!pfile->is_raw_block) {
	pisces_file_close(pfile->file_handle);
    }


    kmem_free(pfile->path);    
    kmem_free(pfile);

    return 0;
}

static loff_t
palacios_file_size(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    if (pfile == NULL) {
        return -1;
    }

    if (!pfile->is_raw_block) {
	return pisces_file_size(pfile->file_handle);
    }

    return blkdev_get_capacity((blkdev_handle_t) pfile->file_handle);
}

static ssize_t 
palacios_file_read(void   * file_ptr, 
		   void   * buffer, 
		   size_t   length, 
		   loff_t   offset)
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
    

    if (pfile->is_raw_block) {
	blk_req_t blkreq; 
	int       ret       = 0;

	blkreq.dma_descs = kmem_alloc(sizeof(blk_dma_desc_t));
	blkreq.desc_cnt  = 1;
	
	blkreq.dma_descs[0].buf_paddr = __pa(buffer);
	blkreq.dma_descs[0].length    = length;

	
	blkreq.total_len = length;
	blkreq.offset    = offset;
	
	ret = blkdev_do_request((blkdev_handle_t)pfile->file_handle, &blkreq);
	
	kmem_free(blkreq.dma_descs);

	if ((ret           != 0) || 
	    (blkreq.status != 0)) 
	{
	    printk(KERN_ERR "Error issuing block request for Palacios file (%s)\n", pfile->path);
	    return 0;
	}


    } else {
	length = pisces_file_read(pfile->file_handle, buffer, length, offset);
    }

    return length;
}


static ssize_t
palacios_file_write(void   * file_ptr, 
		    void   * buffer,
		    size_t   length, 
		    loff_t   offset) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
    

    if (pfile->is_raw_block) {
	blk_req_t blkreq; 
	int       ret       = 0;

	blkreq.dma_descs = kmem_alloc(sizeof(blk_dma_desc_t));
	blkreq.desc_cnt  = 1;
	
	blkreq.dma_descs[0].buf_paddr = __pa(buffer);
	blkreq.dma_descs[0].length    = length;

	
	blkreq.total_len = length;
	blkreq.offset    = offset;
	blkreq.write     = 1;
	
	ret = blkdev_do_request((blkdev_handle_t)pfile->file_handle, &blkreq);
	
	kmem_free(blkreq.dma_descs);

	if ((ret           != 0) || 
	    (blkreq.status != 0)) 
	{
	    printk(KERN_ERR "Error issuing block request for Palacios file (%s)\n", pfile->path);
	    return 0;
	}


    } else {
	length = pisces_file_write(pfile->file_handle, buffer, length, offset);
    }


    return length;
}

static ssize_t 
palacios_file_readv(void     * file_ptr,
		    v3_iov_t * iov_arr, 
		    int        iov_len,
		    loff_t     offset)
{
    struct palacios_file * pfile  = (struct palacios_file *)file_ptr;
    unsigned long long     length = 0;
    int i = 0;

    if (pfile->is_raw_block) {
	blk_req_t blkreq; 
	u64       total_len = 0;
	int       ret       = 0;

        memset(&blkreq, 0, sizeof(blk_req_t));
	blkreq.dma_descs = kmem_alloc(sizeof(blk_dma_desc_t) * iov_len);
	blkreq.desc_cnt  = iov_len;

	for (i = 0; i < iov_len; i++) {
	    blkreq.dma_descs[i].buf_paddr = __pa(iov_arr[i].iov_base);
	    blkreq.dma_descs[i].length    = iov_arr[i].iov_len;
	    total_len                    += iov_arr[i].iov_len;
	}

	
	blkreq.total_len = total_len;
	blkreq.offset    = offset;
	
	ret = blkdev_do_request((blkdev_handle_t)pfile->file_handle, &blkreq);
	
	if ((ret           == 0) && 
	    (blkreq.status == 0)) 
	{
	    length = total_len;
	} else {
	    printk(KERN_ERR "Error issuing block request for Palacios file (%s), ret=%d, status=%d\n", 
                    pfile->path, ret, blkreq.status);
	}

	kmem_free(blkreq.dma_descs);

    } else {

	for (i = 0; i < iov_len; i++) {
	    length += pisces_file_read(pfile->file_handle, iov_arr[i].iov_base, iov_arr[i].iov_len, offset + length);
	}
    }

    return length;
}


static ssize_t 
palacios_file_writev(void     * file_ptr,
		     v3_iov_t * iov_arr, 
		     int        iov_len,
		     loff_t     offset) 
{
    struct palacios_file * pfile  = (struct palacios_file *)file_ptr;
    unsigned long long     length = 0;
    int i = 0;

    if (pfile->is_raw_block) {
	blk_req_t blkreq; 
	u64       total_len = 0;
	int       ret       = 0;

	blkreq.dma_descs = kmem_alloc(sizeof(blk_dma_desc_t) * iov_len);
	blkreq.desc_cnt  = iov_len;

	for (i = 0; i < iov_len; i++) {
	    blkreq.dma_descs[i].buf_paddr = __pa(iov_arr[i].iov_base);
	    blkreq.dma_descs[i].length    = iov_arr[i].iov_len;
	    total_len                    += iov_arr[i].iov_len;
	}

	
	blkreq.total_len = total_len;
	blkreq.offset    = offset;
	blkreq.write     = 1;
	
	ret = blkdev_do_request((blkdev_handle_t)pfile->file_handle, &blkreq);
	
	if ((ret           == 0) && 
	    (blkreq.status == 0)) 
	{
	    length = total_len;
	} else {
	    printk(KERN_ERR "Error issuing block request for Palacios file (%s)\n", pfile->path);
	}

	kmem_free(blkreq.dma_descs);

    } else {
	for (i = 0; i < iov_len; i++) {
	    length += pisces_file_write(pfile->file_handle, iov_arr[i].iov_base, iov_arr[i].iov_len, offset + length);
	}
    }

    return length;

}


static struct v3_file_hooks palacios_file_hooks = {
	.open	= palacios_file_open,
	.close	= palacios_file_close,
	.read	= palacios_file_read,
	.write	= palacios_file_write,
	.readv  = palacios_file_readv,
	.writev = palacios_file_writev,
	.size	= palacios_file_size,
	.mkdir  = palacios_file_mkdir,
};



static int 
file_init( void ) 
{
    V3_Init_File(&palacios_file_hooks);

    return 0;
}


static int 
file_deinit( void ) 
{
    return 0;
}





static struct kitten_ext file_ext = {
    .name         = "FILE_INTERFACE",
    .init         = file_init, 
    .deinit       = file_deinit,
    .guest_init   = NULL,
    .guest_deinit = NULL
};

register_extension(&file_ext);
