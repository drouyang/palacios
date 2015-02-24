/* 
 * V3 Control library functions
 * (c) 2015, Jack lange <jacklange@cs.pitt.edu>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3vee.h"
#include "v3_ioctl.h"

#include <pet_mem.h>
#include <pet_log.h>

int 
v3_is_vmm_present()
{
    int fd = 0;

    fd = open(V3_DEV_FILENAME, O_RDWR);

    if (fd == -1) {
	return 0;
    }

    close(fd);
    return 1;
}

int 
v3_add_cpu(int cpu_id)
{
    return pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_CPU, cpu_id);
}

int 
v3_remove_cpu(int cpu_id)
{
    return pet_ioctl_path(V3_DEV_FILENAME, V3_REMOVE_CPU, cpu_id);
}



int 
v3_add_mem_node(int numa_zone)
{
    struct v3_mem_region   mem_range;
    struct mem_block    * block_arr = NULL;
    int ret = 0;
    int i   = 0;
    int numa_num_blocks = pet_num_blocks(numa_zone);
    
    block_arr = calloc(numa_num_blocks, sizeof(struct mem_block));
 
    ret = pet_offline_mem_node(numa_zone, block_arr);

    for (i = 0; i < numa_num_blocks; i++) {
	mem_range.base_addr = block_arr[i].base_addr;
	mem_range.num_pages = block_arr[i].pages;
	
	printf("Adding memory range (%p) to Palacios\n", 
	       (void *)mem_range.base_addr);
	
	if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_MEM, &mem_range) == -1) {
	    ERROR("Could not add memory to Palacios\n");
	}
    }
    
    free(block_arr);
    
    return ret;
}

int
v3_remove_mem_node(int numa_zone) 
{



    return -1;
}


int 
v3_add_mem(int num_blocks, 
	   int numa_zone) 
{
    struct v3_mem_region   mem_range;
    struct mem_block    * block_arr = NULL;
    int i   = 0;
    int ret = 0;
    
    block_arr = calloc(num_blocks, sizeof(struct mem_block));
    ret       = pet_offline_blocks(num_blocks, numa_zone, block_arr);
    
    if (ret != num_blocks) {
	ERROR("Could not allocate %d memory blocks (ret = %d)\n", num_blocks, ret);
	
	pet_online_blocks(ret, block_arr);
	free(block_arr);
	
	return -1;
    }
    
    for (i = 0; i < num_blocks; i++) {
	mem_range.base_addr = block_arr[i].base_addr;
	mem_range.num_pages = block_arr[i].pages;
	
	printf("Adding memory range (%p) to Palacios\n", 
	       (void *)mem_range.base_addr);
	
	if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_MEM, &mem_range) == -1) {
	    ERROR("Could not add memory to Palacios\n");
	}
    }
    
    free(block_arr);
    
    return 0;
}



int 
v3_remove_mem(int num_blocks,
	      int numa_zone)
{
    int blocks_freed = 0;

    if (num_blocks == 0) {
	return 0;
    }

    if (numa_zone >= 0) {
	char * proc_filename = NULL;
	FILE * proc_file     = NULL;
	char * line          = NULL;
	size_t size          = 0;

	if (asprintf(&proc_filename, "/proc/v3vee/v3-mem%d", numa_zone) == -1) {
	    ERROR("asprintf failed\n");
	    return -1;
	}

	proc_file = fopen(proc_filename, "r");
	
	free(proc_filename);

	if (proc_file == NULL) {
	    ERROR("Could not open proc file for numa zone %d\n", numa_zone);
	    return -1;
	}
	
	printf("Searching for memory pools\n");

	while (getline(&line, &size, proc_file) != -1) {
	    if (strstr(line, "memory pools") != NULL) break;
	}


	printf("iterating over blocks\n");
	while (getline(&line, &size, proc_file) != -1) {
	    u64 base_addr = 0;
	    u32 order     = 0;
	    u32 size      = 0;
	    u32 freed     = 0;
	    
	    int matched   = 0;


	    matched = sscanf(line, "    Base Addr=%llx, order=%u, size=%u, free=%u", 
			     &base_addr, &order, &size, &freed);

	    if (matched == 0) {
		ERROR("Could not match memory pool string\n");
		break;
	    }

	    if (pet_block_size() != (1 << order)) {
		printf("Pool (%p) is not a block\n", (void *)base_addr);
		continue;
	    }


	    printf("base_addr=%llx, order=%u, size=%u, free=%u\n", 
		   base_addr, order, size, freed);


	    if (freed == size) {
		// block is clear, remove it
		printf("attempting to remove block at %p\n", (void *)base_addr);

		
		if (pet_ioctl_path(V3_DEV_FILENAME, V3_REMOVE_MEM, base_addr) == -1) {
		    ERROR("Could not remove memory from Palacios\n");
		    continue;
		}
		
		blocks_freed++;

		if (pet_online_block(base_addr / pet_block_size()) == -1) {
		    ERROR("Block removed from Palacios, but not onlined\n");
		}
	    }


	    if (blocks_freed == num_blocks) break;
	}


	fclose(proc_file);


    } else {
	int i = 0;
	
	for (i = 0; i < pet_num_numa_nodes(); i++) {
	    
	    blocks_freed += v3_remove_mem(num_blocks - blocks_freed, i);
	    
	    if (blocks_freed == num_blocks) break;
	}

    }

    return blocks_freed;
}

int 
v3_add_mem_explicit(int block_id)
{
    struct v3_mem_region mem_range;
  
    if (pet_offline_block(block_id) == -1) {
	ERROR("Could not offline memory block %d\n", block_id);
	return -1;
    }

    mem_range.base_addr = pet_block_size() * block_id;
    mem_range.num_pages = pet_block_size() / 4096;
    
    if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_MEM, &mem_range) == -1) {
	ERROR("Could not add explicit memory block (block_id: %d)\n", block_id); 
	pet_online_block(block_id);
	return -1;
    }
    
    return 0;
}


int 
v3_add_pci(char * name, 
	   u32    bus, 
	   u32    dev,
	   u32    fn)
{
    struct v3_hw_pci_dev dev_spec;

    memset(&dev_spec, 0, sizeof(struct v3_hw_pci_dev));

    dev_spec.bus  = bus;
    dev_spec.dev  = dev;
    dev_spec.func = fn;
    strncpy(dev_spec.url, name, 128);

   if (pet_offline_pci(bus, dev, fn) != 0) {
       ERROR("Could not offline PCI device\n");
       return -1;
   }


   if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_PCI,  &dev_spec) != 0) {
       ERROR("Could not add device to Palacios\n");
       pet_online_pci(bus, dev, fn);
       return -1;
   }
   
   
   return 0;

}


int 
v3_remove_pci(char * name, 
	      u32    bus, 
	      u32    dev, 
	      u32    fn)
{
    struct v3_hw_pci_dev dev_spec;

    memset(&dev_spec, 0, sizeof(struct v3_hw_pci_dev));

    dev_spec.bus  = bus;
    dev_spec.dev  = dev;
    dev_spec.func = fn;
    strncpy(dev_spec.url, name, 128);

    if (pet_ioctl_path(V3_DEV_FILENAME, V3_REMOVE_PCI,  &dev_spec) != 0) {
	ERROR("Could not remove device from Palacios\n");
	//	pet_online_pci(bus, dev, fn);
	return -1;
    }
    
    if (pet_online_pci(bus, dev, fn) != 0) {
	ERROR("Could not online PCI device [%s] (%d:%d.%d)\n", name, bus, dev, fn);
	return -1;
    }


 return 0;

}


int
v3_launch_vm(int vm_id) 
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    ret = pet_ioctl_path(dev_path, V3_VM_LAUNCH, NULL); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not launch vm (%d)\n", vm_id);
	return -1;
    }
    
    return 0;
}


int
v3_stop_vm(int vm_id)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    ret = pet_ioctl_path(dev_path, V3_VM_STOP, NULL); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not stop vm (%d)\n", vm_id);
	return -1;
    }
    
    return 0;
}

int 
v3_free_vm(int vm_id)
{
    return pet_ioctl_path(V3_DEV_FILENAME, V3_FREE_GUEST, vm_id);

}

int 
v3_continue_vm(int vm_id)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    ret = pet_ioctl_path(dev_path, V3_VM_CONTINUE, NULL); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not continue vm (%d)\n", vm_id);
	return -1;
    }
    
    return 0;
}


int 
v3_pause_vm(int vm_id)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    ret = pet_ioctl_path(dev_path, V3_VM_PAUSE, NULL); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not pause vm (%d)\n", vm_id);
	return -1;
    }
    
    return 0;
}


int
v3_simulate_vm(int vm_id, 
	       u32 msecs)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    ret = pet_ioctl_path(dev_path, V3_VM_SIMULATE, msecs); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not simulate vm (%d)\n", vm_id);
	return -1;
    }
    
    return 0;


}


int 
v3_move_vcore(int vm_id,
	      int vcore,
	      int target_pcore)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int ret = 0;

    struct v3_core_move_cmd cmd; 

    memset(&cmd, 0, sizeof(struct v3_core_move_cmd));

    cmd.vcore_id = vcore;
    cmd.pcore_id = target_pcore;

    ret = pet_ioctl_path(dev_path, V3_VM_MOVE_CORE, &cmd); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not move vm %d's vcore (%d)\n", vm_id, vcore);
	return -1;
    }
    
    return 0;


}

int
v3_debug_vm(int vm_id,
	    u32 core,
	    u32 flags)
{

    char * dev_path = get_vm_dev_path(vm_id);
    int    ret      = 0;

    struct v3_debug_cmd cmd;

    memset(&cmd, 0, sizeof(struct v3_debug_cmd));

    cmd.core = core;
    cmd.cmd  = flags;

    ret = pet_ioctl_path(dev_path, V3_VM_DEBUG, &cmd); 

    free(dev_path);

    if (ret < 0) {
	ERROR("Could not send debug command to VM (%d)\n", vm_id);
	return -1;
    }
    
    return 0;


}


int 
v3_load_vm(int    vm_id,
	   char * store,
	   char * url)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int    ret      = 0;

    struct v3_chkpt_info chkpt;

    memset(&chkpt, 0, sizeof(struct v3_chkpt_info));

    if (strlen(store) >= MAX_CHKPT_STORE_LEN) {
	ERROR("Checkpoint store name longer than maximum size (%d)\n",
	       MAX_CHKPT_STORE_LEN);
	return -1;
    }

    if (strlen(url) >= MAX_CHKPT_URL_LEN) {
	ERROR("Checkpoint URL longer than maximum size (%d)\n", 
	       MAX_CHKPT_URL_LEN);
	return -1;
    }    

    strncpy(chkpt.store, store, MAX_CHKPT_STORE_LEN);
    strncpy(chkpt.url,   url,   MAX_CHKPT_URL_LEN);

    ret = pet_ioctl_path(dev_path, V3_VM_LOAD, &chkpt);

    free(dev_path);

    return ret;
}



int 
v3_save_vm(int    vm_id,
	   char * store,
	   char * url)
{
    char * dev_path = get_vm_dev_path(vm_id);
    int    ret      = 0;

    struct v3_chkpt_info chkpt;

    memset(&chkpt, 0, sizeof(struct v3_chkpt_info));

    if (strlen(store) >= MAX_CHKPT_STORE_LEN) {
	ERROR("Checkpoint store name longer than maximum size (%d)\n",
	       MAX_CHKPT_STORE_LEN);
	return -1;
    }

    if (strlen(url) >= MAX_CHKPT_URL_LEN) {
	ERROR("Checkpoint URL longer than maximum size (%d)\n", 
	       MAX_CHKPT_URL_LEN);
	return -1;
    }    

    strncpy(chkpt.store, store, MAX_CHKPT_STORE_LEN);
    strncpy(chkpt.url,   url,   MAX_CHKPT_URL_LEN);

    ret = pet_ioctl_path(dev_path, V3_VM_SAVE, &chkpt);

    free(dev_path);

    return ret;
}
