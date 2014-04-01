/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu>
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>
#include <palacios/vm.h>



void __udelay(unsigned long usecs);


struct disk_state {
    struct v3_dev_blk_ops * ops;
    uint32_t seek_usecs;

    void * private_data;
};


static int model_write(uint8_t * buf,  uint64_t lba, uint64_t num_bytes, void * private_data) {
    struct disk_state * model = (struct disk_state *)private_data;
    
    __udelay(model->seek_usecs);

    return model->ops->write(buf, lba, num_bytes, model->private_data);

}

static int model_read(uint8_t * buf,  uint64_t lba, uint64_t num_bytes, void * private_data) {
    struct disk_state * model = (struct disk_state *)private_data;
    
    __udelay(model->seek_usecs);

    return model->ops->read(buf, lba, num_bytes, model->private_data);

}

static uint64_t model_get_capacity(void * private_data) {
    struct disk_state * model = (struct disk_state *)private_data;

    return model->ops->get_capacity(model->private_data);
}

static int model_free(struct disk_state * model) {

    // unhook from frontend

    V3_Free(model);
    return 0;
}



static struct v3_dev_blk_ops blk_ops = {
    .read = model_read, 
    .write = model_write, 
    .get_capacity = model_get_capacity,
};



static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))model_free,
};


static int connect_fn(struct v3_vm_info * vm, 
		      void * frontend_data, 
		      struct v3_dev_blk_ops * ops, 
		      v3_cfg_tree_t * cfg, 
		      void * private_data) {

  v3_cfg_tree_t * frontend_cfg = v3_cfg_subtree(cfg, "frontend");
  uint32_t seek_time = atoi(v3_cfg_val(cfg, "seek_us"));
  struct disk_state * model = (struct disk_state *)V3_Malloc(sizeof(struct disk_state));

  if (!model) {
      PrintError("Cannot allocate\n");
      return -1;
  }

  model->ops = ops;
  model->seek_usecs = seek_time;
  model->private_data = private_data;

  if (v3_dev_connect_blk(vm, v3_cfg_val(frontend_cfg, "tag"), 
			 &blk_ops, frontend_cfg, model) == -1) {
      PrintError("Could not connect  to frontend %s\n", 
		  v3_cfg_val(frontend_cfg, "tag"));
      return -1;
  }

  return 0;
}

static int model_init(struct v3_vm_info * vm, v3_cfg_tree_t * cfg) {

    char * dev_id = v3_cfg_val(cfg, "ID");

    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, NULL);

    if (dev == NULL) {
	PrintError("Could not attach device %s\n", dev_id);
	return -1;
    }

    if (v3_dev_add_blk_frontend(vm, dev_id, connect_fn, NULL) == -1) {
	PrintError("Could not register %s as block frontend\n", dev_id);
	v3_remove_device(dev);
	return -1;
    }


    return 0;
}



device_register("DISK_MODEL", model_init)
