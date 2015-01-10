/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2011, Jack Lange <jacklange@cs.pitt.edu> 
 * Copyright (c) 2011, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu> 
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __VMM_CHKPT_STORES_H__
#define __VMM_CHKPT_STORES_H__

//#include <palacios/vmm_types.h>

/*
 * This is a place holder to ensure that the _v3_extensions section gets created by gcc
 */
static struct {} null_store __attribute__((__used__))			\
    __attribute__((unused, __section__ ("_v3_chkpt_stores"),		\
                   aligned(sizeof(addr_t))));


#define register_chkpt_store(store)					\
    static struct chkpt_interface * _v3_store_##store			\
    __attribute__((used))						\
	__attribute__((unused, __section__("_v3_chkpt_stores"),		\
		       aligned(sizeof(addr_t))))			\
	= &store;





#include <palacios/vmm_util.h>


static int
__alloc_block_buf(struct chkpt_block * block)
{
 
    /* We don't have to allocate anything for zero copy blocks */
    if (block->zero_copy == 1) {
	return -1;
    }
   
    if (block->block_ptr != NULL) {
	PrintError("Block Buffer ptr is not NULL\n");
	return -1;
    }

    block->block_ptr = V3_Malloc(block->size);

    if (block->block_ptr == NULL)  {
	PrintError("Could not allocate block buffer (size=%lu) for (%s)\n", 
		   block->size, block->name);
	return -1;
    }

    memset(block->block_ptr, 0, block->size);

    return 0;
}


static int
__free_block_buf(struct chkpt_block * block)
{
    if (block->zero_copy == 1) {
	return -1;
    }

    V3_Free(block->block_ptr);

    block->block_ptr = NULL;
    return 0;
}


/*
 * Debug Checkpoint target
 * 
 * Prints Checkpoint contents to the debug log
 */

static void * 
debug_open_chkpt(struct v3_vm_info * vm, 
		 char              * url, 
		 chkpt_mode_t        mode) 
{
   
    if (mode == LOAD) {
	V3_Print("Cannot load from debug store\n");
	return NULL;
    }

    V3_Print("Opening Checkpoint: %s\n", url);

    return (void *)1;
}



static int 
debug_close_chkpt(void * store_data) 
{
    V3_Print("Closing Checkpoint\n");
    return 0;
}


static int 
debug_save(struct chkpt_block * block,
	   void               * store_data)
{
    int len = block->size;

    V3_Print("[%s]\n", block->name);
    
    if (!block->zero_copy) {

	if (__alloc_block_buf(block) == -1) {
	    PrintError("Could not allocate block buffer\n");
	    return -1;
	}
	
	block->save(block->name, block->block_ptr, block->size, block->priv);
    }

    if (len > 100) {
	len = 100;
    }

    v3_dump_mem(block->block_ptr, len);
    
    if (!block->zero_copy) {
	__free_block_buf(block);
    }

    V3_Print("[CLOSE]\n"); 

    return 0;
}

static int 
debug_load(struct chkpt_block * block,
	   void               * store_data) 
{
    V3_Print("Loading not supported !!!\n");
    return 0;
}


static struct chkpt_interface debug_store = {
    .name        = "DEBUG",
    .open_chkpt  = debug_open_chkpt,
    .close_chkpt = debug_close_chkpt,
    .save_block  = debug_save,
    .load_block  = debug_load
};

register_chkpt_store(debug_store);




#ifdef V3_CONFIG_FILE
#include <interfaces/vmm_file.h>

   

static void * 
dir_open_chkpt(struct v3_vm_info * vm,
	       char              * url, 
	       chkpt_mode_t        mode) 
{
    if (mode == SAVE) {
	if (v3_mkdir(url, 0755, 1) != 0) {
	    return NULL;
	}
    }

    return url;
}



static int
dir_close_chkpt(void * store_data) 
{
    return 0;
}

static int
dir_save_block(struct chkpt_block * block,
	       void               * store_data) 
{    
    char * url      = store_data;
    char * filename = NULL;
    int    str_len  = strlen(url) + strlen(block->name) + 5;

    v3_file_t file;
    int ret = 0;


    if (!block->zero_copy) {

	if (__alloc_block_buf(block) == -1) {
	    PrintError("Could not allocate block buffer\n");
	    return -1;
	}
	
	if (block->save(block->name, block->block_ptr, block->size, block->priv) == -1) {
	    PrintError("Could not save block (%s)\n", block->name);
	    ret = -1;
	    goto out3;
	}
    }

    filename = V3_Malloc(str_len);

    if (filename == NULL) {
	PrintError("Could not open file (%s)\n", filename);
	ret = -1;
	goto out3;
    }

    memset(filename,  0, str_len);
    snprintf(filename, str_len, "%s/%s", url, block->name);

    file = v3_file_open(filename, FILE_OPEN_MODE_READ | FILE_OPEN_MODE_WRITE | FILE_OPEN_MODE_CREATE);
   
    if (file == NULL) {
	PrintError("Could not open checkpoint file (%s)\n", filename);

	ret = -1;
	goto out2;
    }

    {
	uint64_t bytes_written = 0;
	loff_t   offset        = 0;
	
	while (bytes_written < block->size) {
	    ssize_t tmp_bytes = v3_file_write(file, 
					      block->block_ptr  + bytes_written,
					      block->size - bytes_written, 
					      offset            + bytes_written);
	    if (tmp_bytes <= 0) {
		PrintError("Error Writing to checkpoint file (%s)\n", filename);
		ret = -1;
		goto out1;
	    }
    
	    bytes_written += tmp_bytes;
	}
    }

 out1:
    v3_file_close(file);
 out2:
    V3_Free(filename);
 out3:
    if (!block->zero_copy) {
	__free_block_buf(block);
    }

    return ret;
}


static int
dir_load_block(struct chkpt_block * block,
	       void               * store_data) 
{    
    char * url      = store_data;
    char * filename = NULL;
    int    str_len  = strlen(url) + strlen(block->name) + 5;

    v3_file_t file;
    int ret = 0;

    if (!block->zero_copy) {
	if (__alloc_block_buf(block) == -1) {
	    PrintError("Could not allocate block buffer\n");
	    return -1;
	}
    
    }


    filename = V3_Malloc(str_len);

    if (filename == NULL) {
	PrintError("Could not open file (%s)\n", filename);
	ret = -1;
	goto out3;
    }

    memset(filename,  0, str_len);
    snprintf(filename, str_len, "%s/%s", url, block->name);

    file = v3_file_open(filename, FILE_OPEN_MODE_READ | FILE_OPEN_MODE_WRITE | FILE_OPEN_MODE_CREATE);
   

    if (file == NULL) {
	PrintError("Could not open checkpoint file (%s)\n", filename);
	ret = -1;
	goto out2;
    }

    {
	uint64_t bytes_read = 0;
	loff_t   offset     = 0;
	
	while (bytes_read < block->size) {
	    ssize_t tmp_bytes = v3_file_read(file, 
					     block->block_ptr  + bytes_read,
					     block->size       - bytes_read, 
					     offset            + bytes_read);
	    if (tmp_bytes <= 0) {
		PrintError("Error Reading from checkpoint file (%s)\n", filename);
		ret = -1;
		goto out1;
	    }
    
	    bytes_read += tmp_bytes;
	}
    }


    if (!block->zero_copy) {

	if (block->load(block->name, block->block_ptr, block->size, block->priv) == -1) {
	    PrintError("Could not save block (%s)\n", block->name);
	    ret = -1;
	    goto out1;
	}
    }

 out1:
    v3_file_close(file);
 out2:
    V3_Free(filename);
 out3:

    if (!block->zero_copy) {
	__free_block_buf(block);
    }

    return ret;
}



static struct chkpt_interface dir_store = {
    .name        = "DIR",
    .open_chkpt  = dir_open_chkpt,
    .close_chkpt = dir_close_chkpt,
    .save_block  = dir_save_block,
    .load_block  = dir_load_block,
};

register_chkpt_store(dir_store);



#endif







#endif
