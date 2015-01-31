/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2010, Peter Dinda <pdinda@northwestern.edu> 
 * Copyright (c) 2010, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Peter Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <interfaces/vmm_file.h>
#include <palacios/vmm.h>
#include <palacios/vmm_debug.h>
#include <palacios/vmm_types.h>
#include <palacios/vm.h>

static struct v3_file_hooks * file_hooks = NULL;

void 
V3_Init_File(struct v3_file_hooks * hooks) 
{
    file_hooks = hooks;
    V3_Print("V3 file interface intialized\n");
    return;
}


int 
v3_mkdir(char     * path, 
	 uint16_t   permissions, 
	 uint8_t    recursive) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->mkdir);
    
    return file_hooks->mkdir(path, permissions, recursive);
}


v3_file_t 
v3_file_open(char              * path, 
	     int                 mode)
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->open);
    
    return file_hooks->open(path, mode);
}

int 
v3_file_close(v3_file_t file) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->close);
    
    return file_hooks->close(file);
}

loff_t
v3_file_size(v3_file_t file) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->size);
    
    return file_hooks->size(file);
}

ssize_t
v3_file_read(v3_file_t   file, 
	     uint8_t   * buf, 
	     size_t      len, 
	     loff_t      off) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->read);
    
    return file_hooks->read(file, buf, len, off);
}


ssize_t
v3_file_write(v3_file_t   file, 
	      uint8_t   * buf,
	      size_t      len, 
	      loff_t      off) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->write);
    
    return file_hooks->write(file, buf, len, off);
}


ssize_t
v3_file_readv(v3_file_t   file, 
	      v3_iov_t  * iov_arr,
	      int         iov_len,
	      loff_t      off) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->readv);
    
    return file_hooks->readv(file, iov_arr, iov_len, off);
}


ssize_t
v3_file_writev(v3_file_t   file, 
	       v3_iov_t  * iov_arr,
	       int         iov_len,
	       loff_t      off) 
{
    V3_ASSERT(file_hooks);
    V3_ASSERT(file_hooks->writev);
    
    return file_hooks->writev(file, iov_arr, iov_len, off);
}
