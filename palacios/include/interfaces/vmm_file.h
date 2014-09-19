/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2010, Peter Dinda (pdinda@cs.northwestern.edu> 
 * Copyright (c) 2010, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Peter Dinda <pdinda@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#ifndef __VMM_FILE_H__
#define __VMM_FILE_H__

#include <palacios/vmm.h>
#include <palacios/vmm_types.h>

#ifdef __V3VEE__
typedef void * v3_file_t;

int v3_mkdir(char * path, uint16_t permissions, uint8_t recursive);

v3_file_t v3_file_open(struct v3_vm_info * vm, char * path, int mode);
int v3_file_close(v3_file_t file);
loff_t v3_file_size(v3_file_t file);

ssize_t v3_file_read(v3_file_t file, uint8_t * buf, size_t len, loff_t off);
ssize_t v3_file_write(v3_file_t file, uint8_t * buf, size_t len, loff_t off);

ssize_t v3_file_writev(v3_file_t file, v3_iov_t * iov_arr, int iov_len, loff_t off);
ssize_t v3_file_readv(v3_file_t file, v3_iov_t * iov_arr, int iov_len, loff_t off);

#endif

#define FILE_OPEN_MODE_READ	  (0x1 << 0)
#define FILE_OPEN_MODE_WRITE      (0x1 << 1)
#define FILE_OPEN_MODE_CREATE     (0x1 << 2)
#define FILE_OPEN_MODE_RAW_BLOCK  (0x1 << 31)




struct v3_file_hooks {
    int (*mkdir)(const char * path, unsigned short perms, int recursive);

    void * (*open)(const char * path, int mode, void * host_data);
    int    (*close)(void * fd);

    loff_t (*size)(void * fd);

    // blocking reads and writes
    ssize_t (*read)(void * fd, void * buffer, size_t length, loff_t offset);
    ssize_t (*write)(void * fd, void * buffer, size_t length, loff_t offset);
    

    ssize_t (*readv)(void     * fd, 
		     v3_iov_t * iov_arr, 
		     int        iov_len, 
		     loff_t     offset);


    ssize_t (*writev)(void     * fd, 
		      v3_iov_t * iov_arr, 
		      int        iov_len, 
		      loff_t     offset);

};


extern void V3_Init_File(struct v3_file_hooks * hooks);

#endif
