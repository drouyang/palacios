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


#include <palacios/vmm_msr.h>
#include <palacios/vmm.h>
#include <palacios/vm_guest.h>


void v3_init_msr_map(struct guest_info * info) {
  struct v3_msr_map * msr_map  = &(info->msr_map);

  INIT_LIST_HEAD(&(msr_map->hook_list));
  msr_map->num_hooks = 0;
}


int v3_hook_msr(struct guest_info * info, uint_t msr, 
		int (*read)(uint_t msr, struct v3_msr * dst, void * priv_data),
		int (*write)(uint_t msr, struct v3_msr src, void * priv_data),
		void * priv_data) {

  struct v3_msr_map * msr_map = &(info->msr_map);
  struct v3_msr_hook * hook = NULL;

  hook = (struct v3_msr_hook *)V3_Malloc(sizeof(struct v3_msr_hook));
  if (hook == NULL) {
    PrintError("Could not allocate msr hook for MSR %d\n", msr);
    return -1;
  }

  hook->read = read;
  hook->write = write;
  hook->msr = msr;
  hook->priv_data = priv_data;

  msr_map->num_hooks++;

  list_add(&(hook->link), &(msr_map->hook_list));

  return 0;
}


int v3_unhook_msr(struct guest_info * info, uint_t msr) {
  return -1;
}



struct v3_msr_hook * v3_get_msr_hook(struct guest_info * info, uint_t msr) {
  struct v3_msr_map * msr_map = &(info->msr_map);
  struct v3_msr_hook * hook = NULL;

  list_for_each_entry(hook, &(msr_map->hook_list), link) {
    if (hook->msr == msr) {
      return hook;
    }
  }

  return NULL;
}


void v3_print_msr_map(struct guest_info * info) {
  struct v3_msr_map * msr_map = &(info->msr_map);
  struct v3_msr_hook * hook = NULL;

  list_for_each_entry(hook, &(msr_map->hook_list), link) {
    PrintDebug("MSR HOOK (MSR=%d) (read=0x%p) (write=0x%p)\n",
	       hook->msr, hook->read, hook->write);
  }
}
