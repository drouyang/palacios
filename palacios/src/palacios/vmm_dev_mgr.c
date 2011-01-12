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

#include <palacios/vmm_dev_mgr.h>
#include <palacios/vm_guest.h>
#include <palacios/vmm.h>
#include <palacios/vmm_decoder.h>


#ifndef CONFIG_DEBUG_DEV_MGR
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif


static struct hashtable * master_dev_table = NULL;

static uint_t dev_hash_fn(addr_t key) {
    char * name = (char *)key;
    return v3_hash_buffer((uchar_t *)name, strlen(name));
}

static int dev_eq_fn(addr_t key1, addr_t key2) {
    char * name1 = (char *)key1;
    char * name2 = (char *)key2;
    
    return (strcmp(name1, name2) == 0);
}


int V3_init_devices() {
    extern struct v3_device_info __start__v3_devices[];
    extern struct v3_device_info __stop__v3_devices[];
    struct v3_device_info * tmp_dev =  __start__v3_devices;
    int i = 0;

#ifdef CONFIG_DEBUG_DEV_MGR
    {
	int num_devices = (__stop__v3_devices - __start__v3_devices) / sizeof(struct v3_device_info);
	PrintDebug("%d Virtual devices registered with Palacios\n", num_devices);
    }
#endif

    PrintDebug("Start addres=%p, Stop address=%p\n", __start__v3_devices, __stop__v3_devices);

    master_dev_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);



    while (tmp_dev != __stop__v3_devices) {
	PrintDebug("Device: %s\n", tmp_dev->name);

	if (v3_htable_search(master_dev_table, (addr_t)(tmp_dev->name))) {
	    PrintError("Multiple instance of device (%s)\n", tmp_dev->name);
	    return -1;
	}

	if (v3_htable_insert(master_dev_table, 
			     (addr_t)(tmp_dev->name), 
			     (addr_t)(tmp_dev->init)) == 0) {
	    PrintError("Could not add device %s to master list\n", tmp_dev->name);
	    return -1;
	}

	tmp_dev = &(__start__v3_devices[++i]);
    }


    return 0;
}


int v3_init_dev_mgr(struct v3_vm_info * vm) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);

    INIT_LIST_HEAD(&(mgr->dev_list));
    mgr->num_devs = 0;

    mgr->dev_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);

    INIT_LIST_HEAD(&(mgr->blk_list));
    INIT_LIST_HEAD(&(mgr->net_list));
    INIT_LIST_HEAD(&(mgr->char_list));
    INIT_LIST_HEAD(&(mgr->cons_list));

    mgr->blk_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);
    mgr->net_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);
    mgr->char_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);
    mgr->cons_table = v3_create_htable(0, dev_hash_fn, dev_eq_fn);
    
    return 0;
}


int v3_free_vm_devices(struct v3_vm_info * vm) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);
    struct vm_device * dev;
    struct vm_device * tmp;

    list_for_each_entry_safe(dev, tmp, &(mgr->dev_list), dev_link) {
	v3_remove_device(dev);
    }

    return 0;
}

int v3_deinit_dev_mgr(struct v3_vm_info * vm) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);

    v3_free_htable(mgr->blk_table, 0, 0);
    v3_free_htable(mgr->net_table, 0, 0);
    v3_free_htable(mgr->char_table, 0, 0);
    v3_free_htable(mgr->cons_table, 0, 0);

    v3_free_htable(mgr->dev_table, 0, 0);

    return 0;
}



int v3_create_device(struct v3_vm_info * vm, const char * dev_name, v3_cfg_tree_t * cfg) {
    int (*dev_init)(struct v3_vm_info * vm, void * cfg_data);

    dev_init = (void *)v3_htable_search(master_dev_table, (addr_t)dev_name);

    if (dev_init == NULL) {
	PrintError("Could not find device %s in master device table\n", dev_name);
	return -1;
    }


    if (dev_init(vm, cfg) == -1) {
	PrintError("Could not initialize Device %s\n", dev_name);
	return -1;
    }

    return 0;
}




struct vm_device * v3_find_dev(struct v3_vm_info * vm, const char * dev_name) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);

    if (!dev_name) {
	return NULL;
    }

    return (struct vm_device *)v3_htable_search(mgr->dev_table, (addr_t)dev_name);
}


/****************************************************************/
/* The remaining functions are called by the devices themselves */
/****************************************************************/

struct dev_io_hook {
    uint16_t port;

    struct list_head node;

};

/* IO HOOKS */
int v3_dev_hook_io(struct vm_device * dev, uint16_t port,
		   int (*read)(struct guest_info * core, uint16_t port, void * dst, uint_t length, void * priv_data),
		   int (*write)(struct guest_info * core, uint16_t port, void * src, uint_t length, void * priv_data)) {
    struct dev_io_hook * io_hook = NULL;
    int ret = 0;
    
   ret = v3_hook_io_port(dev->vm, port, 
			 (int (*)(struct guest_info * core, ushort_t, void *, uint_t, void *))read, 
			 (int (*)(struct guest_info * core, ushort_t, void *, uint_t, void *))write, 
			 (void *)dev->private_data);

   if (ret == -1) {
       return -1;
   }

   io_hook = V3_Malloc(sizeof(struct dev_io_hook));

   if (io_hook == NULL) {
       PrintError("Could not allocate io hook dev state\n");
       return -1;
   }

   io_hook->port = port;
   list_add(&(io_hook->node), &(dev->io_hooks));

   return 0;
}


int v3_dev_unhook_io(struct vm_device * dev, uint16_t port) {
    struct dev_io_hook * io_hook = NULL;
    struct dev_io_hook * tmp;

    list_for_each_entry_safe(io_hook, tmp, &(dev->io_hooks), node) {
	if (io_hook->port == port) {

	    list_del(&(io_hook->node));
	    V3_Free(io_hook);
	    
	    return v3_unhook_io_port(dev->vm, port);	    
	}
    }

    return -1;
}



int v3_remove_device(struct vm_device * dev) {
    struct vmm_dev_mgr * mgr = &(dev->vm->dev_mgr);
    struct dev_io_hook * io_hook = NULL;
    struct dev_io_hook * tmp;

    list_for_each_entry_safe(io_hook, tmp, &(dev->io_hooks), node) {
	v3_unhook_io_port(dev->vm, io_hook->port);	    
	list_del(&(io_hook->node));
	V3_Free(io_hook);    
    }

    if (dev->ops->free) {
	dev->ops->free(dev->private_data);
    } else {
	PrintError("Error: %s free() not implemented\n",  dev->name);
    }

    list_del(&(dev->dev_link));
    mgr->num_devs--;

    dev->vm = NULL;

    V3_Free(dev);
    return -1;
}


struct vm_device * v3_add_device(struct v3_vm_info * vm,
				 char * name, 
				 struct v3_device_ops * ops, 
				 void * private_data) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);
    struct vm_device * dev = NULL;

    dev = (struct vm_device *)V3_Malloc(sizeof(struct vm_device));

    if (dev == NULL) {
	return NULL;
    }

    INIT_LIST_HEAD(&(dev->io_hooks));

    strncpy(dev->name, name, 32);
    dev->ops = ops;
    dev->private_data = private_data;

    dev->vm = vm;

    list_add(&(dev->dev_link), &(mgr->dev_list));
    mgr->num_devs++;

    v3_htable_insert(mgr->dev_table, (addr_t)(dev->name), (addr_t)dev);

    return dev;
}


void v3_print_dev_mgr(struct v3_vm_info * vm) {
    struct vmm_dev_mgr * mgr = &(vm->dev_mgr);
    struct vm_device * dev;

    V3_Print("%d devices registered with manager\n", mgr->num_devs);

    list_for_each_entry(dev, &(mgr->dev_list), dev_link) {
	V3_Print("Device: %s\n", dev->name);
    }

    return;
}




struct blk_frontend {
    int (*connect)(struct v3_vm_info * vm, 
		    void * frontend_data, 
		    struct v3_dev_blk_ops * ops, 
		    v3_cfg_tree_t * cfg, 
		    void * priv_data);
	

    struct list_head blk_node;

    void * priv_data;
};



int v3_dev_add_blk_frontend(struct v3_vm_info * vm, 
			    char * name, 
			    int (*connect)(struct v3_vm_info * vm, 
					    void * frontend_data, 
					    struct v3_dev_blk_ops * ops, 
					    v3_cfg_tree_t * cfg, 
					    void * priv_data), 
			    void * priv_data) {

    struct blk_frontend * frontend = NULL;

    frontend = (struct blk_frontend *)V3_Malloc(sizeof(struct blk_frontend));
    memset(frontend, 0, sizeof(struct blk_frontend));
    
    frontend->connect = connect;
    frontend->priv_data = priv_data;
	
    list_add(&(frontend->blk_node), &(vm->dev_mgr.blk_list));
    v3_htable_insert(vm->dev_mgr.blk_table, (addr_t)(name), (addr_t)frontend);

    return 0;
}

int v3_dev_connect_blk(struct v3_vm_info * vm, 
		       char * frontend_name, 
		       struct v3_dev_blk_ops * ops, 
		       v3_cfg_tree_t * cfg, 
		       void * private_data) {

    struct blk_frontend * frontend = NULL;

    frontend = (struct blk_frontend *)v3_htable_search(vm->dev_mgr.blk_table,
						       (addr_t)frontend_name);
    
    if (frontend == NULL) {
	PrintError("Could not find frontend blk device %s\n", frontend_name);
	return 0;
    }

    if (frontend->connect(vm, frontend->priv_data, ops, cfg, private_data) == -1) {
	PrintError("Error connecting to block frontend %s\n", frontend_name);
	return -1;
    }

    return 0;
}



struct net_frontend {
    int (*connect)(struct v3_vm_info * vm, 
		    void * frontend_data, 
		    struct v3_dev_net_ops * ops, 
		    v3_cfg_tree_t * cfg, 
		    void * priv_data);
    

    struct list_head net_node;

    void * priv_data;
};


int v3_dev_add_net_frontend(struct v3_vm_info * vm, 
			    char * name, 
			    int (*connect)(struct v3_vm_info * vm, 
					    void * frontend_data, 
					    struct v3_dev_net_ops * ops, 
					    v3_cfg_tree_t * cfg, 
					    void * private_data), 
			    void * priv_data)
{
    struct net_frontend * frontend = NULL;

    frontend = (struct net_frontend *)V3_Malloc(sizeof(struct net_frontend));
    memset(frontend, 0, sizeof(struct net_frontend));
    
    frontend->connect = connect;
    frontend->priv_data = priv_data;
	
    list_add(&(frontend->net_node), &(vm->dev_mgr.net_list));
    v3_htable_insert(vm->dev_mgr.net_table, (addr_t)(name), (addr_t)frontend);

    return 0;
}


int v3_dev_connect_net(struct v3_vm_info * vm, 
		       char * frontend_name, 
		       struct v3_dev_net_ops * ops, 
		       v3_cfg_tree_t * cfg, 
		       void * private_data)
{
    struct net_frontend * frontend = NULL;

    frontend = (struct net_frontend *)v3_htable_search(vm->dev_mgr.net_table,
						       (addr_t)frontend_name);
    
    if (frontend == NULL) {
	PrintError("Could not find frontend net device %s\n", frontend_name);
	return 0;
    }

    if (frontend->connect(vm, frontend->priv_data, ops, cfg, private_data) == -1) {
	PrintError("Error connecting to net frontend %s\n", frontend_name);
	return -1;
    }

    return 0;
}


struct cons_frontend {
    int (*connect)(struct v3_vm_info * vm, 
		   void * frontend_data, 
		   struct v3_dev_console_ops * ops, 
		   v3_cfg_tree_t * cfg, 
		   void * priv_data);
    

    struct list_head cons_node;

    void * priv_data;
};

int v3_dev_add_console_frontend(struct v3_vm_info * vm, 
				char * name, 
				int (*connect)(struct v3_vm_info * vm, 
					       void * frontend_data, 
					       struct v3_dev_console_ops * ops, 
					       v3_cfg_tree_t * cfg, 
					       void * private_data), 
				void * priv_data)
{
    struct cons_frontend * frontend = NULL;

    frontend = (struct cons_frontend *)V3_Malloc(sizeof(struct cons_frontend));
    memset(frontend, 0, sizeof(struct cons_frontend));
    
    frontend->connect = connect;
    frontend->priv_data = priv_data;
	
    list_add(&(frontend->cons_node), &(vm->dev_mgr.cons_list));
    v3_htable_insert(vm->dev_mgr.cons_table, (addr_t)(name), (addr_t)frontend);

    return 0;
}


int v3_dev_connect_console(struct v3_vm_info * vm, 
			   char * frontend_name, 
			   struct v3_dev_console_ops * ops, 
			   v3_cfg_tree_t * cfg, 
			   void * private_data)
{
    struct cons_frontend * frontend = NULL;

    frontend = (struct cons_frontend *)v3_htable_search(vm->dev_mgr.cons_table,
							(addr_t)frontend_name);
    
    if (frontend == NULL) {
	PrintError("Could not find frontend console device %s\n", frontend_name);
	return 0;
    }
    
    if (frontend->connect(vm, frontend->priv_data, ops, cfg, private_data) == -1) {
	PrintError("Error connecting to console frontend %s\n", frontend_name);
	return -1;
    }

    return 0;
}

struct char_frontend {
    int (*connect)(struct v3_vm_info * vm, 
		   void * frontend_data, 
		   struct v3_dev_char_ops * ops, 
		   v3_cfg_tree_t * cfg, 
		   void * priv_data, 
		   void ** push_fn_arg);
    

    struct list_head char_node;

    void * priv_data;
};

int v3_dev_add_char_frontend(struct v3_vm_info * vm, 
			     char * name, 
			     int (*connect)(struct v3_vm_info * vm, 
					    void * frontend_data, 
					    struct v3_dev_char_ops * ops, 
					    v3_cfg_tree_t * cfg, 
					    void * private_data, 
					    void ** push_fn_arg), 
			     void * priv_data)
{
    struct char_frontend * frontend = NULL;

    frontend = (struct char_frontend *)V3_Malloc(sizeof(struct char_frontend));
    memset(frontend, 0, sizeof(struct char_frontend));
    
    frontend->connect = connect;
    frontend->priv_data = priv_data;
	
    list_add(&(frontend->char_node), &(vm->dev_mgr.char_list));
    v3_htable_insert(vm->dev_mgr.char_table, (addr_t)(name), (addr_t)frontend);

    return 0;
}


int v3_dev_connect_char(struct v3_vm_info * vm, 
			char * frontend_name, 
			struct v3_dev_char_ops * ops, 
			v3_cfg_tree_t * cfg, 
			void * private_data, 
			void ** push_fn_arg)
{
    struct char_frontend * frontend = NULL;

    frontend = (struct char_frontend *)v3_htable_search(vm->dev_mgr.char_table,
							(addr_t)frontend_name);
    
    if (frontend == NULL) {
	PrintError("Could not find frontend char device %s\n", frontend_name);
	return 0;
    }
    
    if (frontend->connect(vm, frontend->priv_data, ops, cfg, private_data, push_fn_arg) == -1) {
	PrintError("Error connecting to char frontend %s\n", frontend_name);
	return -1;
    }

    return 0;
}

