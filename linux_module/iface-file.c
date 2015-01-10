/* Palacios file interface 
 * (c) Jack Lange, 2010
 */


#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/uio.h>

#include "palacios.h"
#include "mm.h"
#include "linux-exts.h"
#include "util-hashtable.h"

#include <interfaces/vmm_file.h>

static struct list_head   global_files;
static struct hashtable * file_table = NULL;
struct mutex file_lock;

u32 
file_hash_fn(uintptr_t key) {
    return palacios_hash_buffer((char *)key, strlen((char *)key));
}

int
file_eq_fn(uintptr_t key1, uintptr_t key2) {
    char * str1 = (char *)key1;
    char * str2 = (char *)key2;
  
    if (strlen(str1) != strlen(str2)) {
	return strlen(str1) > strlen(str2);
    }

    return strncmp(str1, str2, strlen(str1));
}


#define isprint(a) ((a >= ' ') && (a <= '~'))

struct palacios_file {
    struct file * filp;

    char * path;
    int    mode;
    
    struct kref  refcount;

    int persistent;     /*  0: discard file handle on last close after open
			 *  1: keep file handle until explicitly removed
			 */

    int opened;         /* Set when the file has been opened the first time */ 

    struct list_head  file_node;
};




static int palacios_file_mkdir(const char * pathname, unsigned short perms, int recurse);

static int
mkdir_recursive(const char     * path, 
		unsigned short   perms) 
{
    char * tmp_str      = NULL;
    char * dirname_ptr  = NULL;
    char * tmp_iter     = NULL;

    tmp_str = palacios_kmalloc(strlen(path) + 1, GFP_KERNEL);
    if (!tmp_str) { 
	ERROR("Cannot allocate in mkdir recursive\n");
	return -1;
    }

    memset( tmp_str, 0,    strlen(path) + 1);
    strncpy(tmp_str, path, strlen(path));

    dirname_ptr = tmp_str;
    tmp_iter    = tmp_str;

    // parse path string, call palacios_file_mkdir recursively.


    while (dirname_ptr != NULL) {
	int done = 0;

	while ( (*tmp_iter != '/') && 
		(*tmp_iter != '\0') ) {

	    if ( (!isprint(*tmp_iter))) {
		ERROR("Invalid character in path name (%d)\n", *tmp_iter);
		palacios_kfree(tmp_str);
		return -1;
	    } else {
		tmp_iter++;
	    }
	}

	if (*tmp_iter == '/') {
	    *tmp_iter = '\0';
	} else {
	    done = 1;
	}

	// Ignore empty directories
	if ((tmp_iter - dirname_ptr) > 1) {
	    if (palacios_file_mkdir(tmp_str, perms, 0) != 0) {
		ERROR("Could not create directory (%s)\n", tmp_str);
		palacios_kfree(tmp_str);
		return -1;
	    }
	}

	if (done) {
	    break;
	} else {
	    *tmp_iter = '/';
	}
	
	tmp_iter++;

	dirname_ptr = tmp_iter;
    }
    
    palacios_kfree(tmp_str);

    return 0;
}

static int 
palacios_file_mkdir(const char     * pathname,
		    unsigned short   perms, 
		    int              recurse) 
{
    /* Welcome to the jungle... */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,41)
    /* DO NOT REFERENCE THIS VARIABLE */
    /* It only exists to provide version compatibility */
    struct path tmp_path; 
#endif

    struct path   * path_ptr = NULL;
    struct dentry * dentry   = NULL;
    int ret = 0;



    if (recurse != 0) {
	return mkdir_recursive(pathname, perms);
    } 

    /* Before Linux 3.1 this was somewhat more difficult */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,41)
    {
	struct nameidata nd;

	// I'm not 100% sure about the version here, but it was around this time that the API changed
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38) 
	ret = kern_path_parent(pathname, &nd);
#else 

	if (path_lookup(pathname, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &nd) == 0) {
	    return 0;
	}

	if (path_lookup(pathname, LOOKUP_PARENT    | LOOKUP_FOLLOW, &nd) != 0) {
	    return -1;
	}
#endif

	if (ret != 0) {
	    ERROR("%s:%d - Error: kern_path_parent() returned error for (%s)\n", __FILE__, __LINE__, 
		   pathname);
	    return -1;
	}
	
	dentry   = lookup_create(&nd, 1);
	path_ptr = &(nd.path);
    }
#else 
    {
	dentry = kern_path_create(AT_FDCWD, pathname, &tmp_path, 1);
	
	if (IS_ERR(dentry)) {
	    return 0;
	}
	
	path_ptr = &tmp_path;
    }
#endif    


    if (!IS_ERR(dentry)) {
	ret = vfs_mkdir(path_ptr->dentry->d_inode, dentry, perms);
    }

    mutex_unlock(&(path_ptr->dentry->d_inode->i_mutex));
    path_put(path_ptr);

    return ret;
}


static void * 
palacios_file_open(const char * path,
		   int          mode) 
{
    struct palacios_file * pfile    = NULL;	    

    if (mode & FILE_OPEN_MODE_RAW_BLOCK) {
	ERROR("Raw Block Access is not supported under Linux\n");
	return NULL;
    }


    /* Try to find an open file */

    mutex_lock(&file_lock);
    {
	pfile = (struct palacios_file *)palacios_htable_search(file_table, (uintptr_t)path);
    }
    mutex_unlock(&file_lock);

    if (pfile != NULL) {

	kref_get(&(pfile->refcount));

	return pfile;
    }


    /* If not available attempt to fall back to root fs */

    
    pfile = palacios_kmalloc(sizeof(struct palacios_file), GFP_KERNEL);
    if (!pfile) { 
	ERROR("Cannot allocate in file open\n");
	return NULL;
    }
    memset(pfile, 0, sizeof(struct palacios_file));

    kref_init(&(pfile->refcount));    

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


    pfile->mode |= O_LARGEFILE;


    pfile->filp = filp_open(path, pfile->mode, 0);
    
    if (IS_ERR(pfile->filp)) {
	ERROR("Cannot open file: %s\n", path);
	palacios_kfree(pfile);
	return NULL;
    }

    pfile->path = palacios_kmalloc(strlen(path), GFP_KERNEL);
    
    if (!pfile->path) { 
	ERROR("Cannot allocate in file open\n");
	filp_close(pfile->filp, NULL);
	palacios_kfree(pfile);
	return NULL;
    }
    strncpy(pfile->path, path, strlen(path));
    
    mutex_lock(&(file_lock));
    {
	struct palacios_file * tmp_file = NULL;

	tmp_file = (struct palacios_file *)palacios_htable_search(file_table, (uintptr_t)path);

	if (tmp_file != NULL) {
	    kref_get(&(pfile->refcount));

	    filp_close(pfile->filp, NULL);
	    palacios_kfree(pfile->path);
	    palacios_kfree(pfile);

	    pfile = tmp_file;

	} else {

	    list_add(&(pfile->file_node), &(global_files));
	    palacios_htable_insert(file_table, (uintptr_t)(pfile->path), (uintptr_t)pfile);
	}
    }
    mutex_unlock(&file_lock);



    return pfile;
}



static void 
file_last_close(struct kref * kref)
{
    struct palacios_file * pfile = container_of(kref, struct palacios_file, refcount);

   
    mutex_lock(&file_lock);
    {
	list_del(&(pfile->file_node));
	palacios_htable_remove(file_table, (uintptr_t)(pfile->path), 0);
    }
    mutex_unlock(&file_lock);

    filp_close(pfile->filp, NULL);
    palacios_kfree(pfile->path);    
    palacios_kfree(pfile);

    return;
}
 

static int 
palacios_file_close(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;

    kref_put(&(pfile->refcount), file_last_close);

    return 0;
}





static loff_t
palacios_file_size(void * file_ptr) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
    struct file          * filp  = pfile->filp;
    struct kstat s;
    int ret;
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,5)
    ret = vfs_getattr(filp->f_path.mnt, filp->f_path.dentry, &s);
#else 
    ret = vfs_getattr(&(filp->f_path), &s);
#endif

    if (ret != 0) {
	ERROR("Failed to fstat file\n");
	return -1;
    }

    return s.size;
}

static ssize_t
palacios_file_read(void   * file_ptr, 
		   void   * buffer, 
		   size_t   length, 
		   loff_t   offset)
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
    struct file          * filp  = pfile->filp;
    mm_segment_t old_fs;
    ssize_t      ret = 0;;
	
    old_fs = get_fs();
    set_fs(get_ds());
	
    ret = vfs_read(filp, buffer, length, &offset);
	
    set_fs(old_fs);
	
    if (ret <= 0) {
	ERROR("sys_read of %p for %ld bytes at offset %lld failed (ret=%ld)\n", filp, length, offset, ret);
    }
	
    return ret;
}


static ssize_t 
palacios_file_write(void   * file_ptr, 
		    void   * buffer, 
		    size_t   length,
		    loff_t   offset) 
{
    struct palacios_file * pfile = (struct palacios_file *)file_ptr;
    struct file          * filp  = pfile->filp;
    mm_segment_t old_fs;
    ssize_t      ret = 0;

    old_fs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(filp, buffer, length, &offset);
	
    set_fs(old_fs);

 
    if (ret <= 0) {
	ERROR("sys_write for %lu bytes at offset %lld failed (ret=%ld)\n", length, offset, ret);
    }
	
    return ret;
}





static ssize_t
palacios_file_readv(void     * file_ptr, 
		    v3_iov_t * iov_arr, 
		    int        iov_len,
		    loff_t     offset)
{
    struct palacios_file * pfile   = (struct palacios_file *)file_ptr;
    struct file          * filp    = pfile->filp;
    struct iovec         * lnx_iov = NULL;        

    u64          total_len = 0;
    mm_segment_t old_fs;
    ssize_t      ret = 0;
    int          i   = 0;

    lnx_iov = palacios_kmalloc(sizeof(struct iovec) * iov_len, GFP_KERNEL);

    if (!lnx_iov) {
	return 0;
    }
    
    for (i = 0; i < iov_len; i++) {
	lnx_iov[i].iov_base = iov_arr[i].iov_base;
	lnx_iov[i].iov_len  = iov_arr[i].iov_len;
	total_len          += iov_arr[i].iov_len;
    }

    old_fs = get_fs();
    set_fs(get_ds());
	
    ret = vfs_readv(filp, lnx_iov, iov_len, &offset);
	
    set_fs(old_fs);

    palacios_kfree(lnx_iov);
	
    if (ret <= 0) {
	ERROR("vfs_readv of %p for %llu bytes at offset %llu failed (ret=%ld)\n", filp, total_len, offset, ret);
    }
	
    return ret;
}


static ssize_t 
palacios_file_writev(void     * file_ptr, 
		     v3_iov_t * iov_arr, 
		     int        iov_len,
		     loff_t     offset) 
{
    struct palacios_file * pfile   = (struct palacios_file *)file_ptr;
    struct file          * filp    = pfile->filp;
    struct iovec         * lnx_iov = NULL;       

    u64          total_len = 0; 
    mm_segment_t old_fs;
    ssize_t      ret = 0;
    int          i   = 0;

    lnx_iov = palacios_kmalloc(sizeof(struct iovec) * iov_len, GFP_KERNEL);

    if (!lnx_iov) {
	return 0;
    }
    
    for (i = 0; i < iov_len; i++) {
	lnx_iov[i].iov_base = iov_arr[i].iov_base;
	lnx_iov[i].iov_len  = iov_arr[i].iov_len;
	total_len          += iov_arr[i].iov_len;
    }
    

    old_fs = get_fs();
    set_fs(get_ds());

    ret = vfs_writev(filp, lnx_iov, iov_len, &offset);
	
    set_fs(old_fs);

    palacios_kfree(lnx_iov);

    if (ret <= 0) {
	ERROR("sys_write for %llu bytes at offset %llu failed (ret=%ld)\n", total_len, offset, ret);
    }
	
    return ret;
}




static struct v3_file_hooks palacios_file_hooks = {
	.mkdir          = palacios_file_mkdir,
	.size		= palacios_file_size,
	.open		= palacios_file_open,
	.close		= palacios_file_close,
	.read		= palacios_file_read,
	.write		= palacios_file_write,
	.readv          = palacios_file_readv,
	.writev         = palacios_file_writev
};



static int
file_init( void ) 
{
    mutex_init(&file_lock);
    INIT_LIST_HEAD(&(global_files));
    file_table = palacios_create_htable(0, file_hash_fn, file_eq_fn);

    V3_Init_File(&palacios_file_hooks);

    /*
    add_global_ctrl(V3_REGISTER_FILE,  register_file);
    add_global_ctrl(V3_REMOVE_FILE,    remove_file);
    */
    return 0;
}


static int 
file_deinit( void )
{
    struct palacios_file * pfile = NULL;
    struct palacios_file * tmp   = NULL;
    
    list_for_each_entry_safe(pfile, tmp, &(global_files), file_node) { 
        filp_close(pfile->filp, NULL);

	palacios_htable_remove(file_table, (uintptr_t)(pfile->path), 0);
        list_del(&(pfile->file_node));

        palacios_kfree(pfile->path);
        palacios_kfree(pfile);
    }

    palacios_free_htable(file_table, 0, 0);

    return 0;
}




static struct linux_ext file_ext = {
    .name         = "FILE_INTERFACE",
    .init         = file_init, 
    .deinit       = file_deinit,
};


register_extension(&file_ext);
