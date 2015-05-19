/* 
 * Copyright (c) 2015, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_types.h>
#include <palacios/vmm_extensions.h>
#include <palacios/vmm_cpuid.h>
#include <palacios/vm.h>
#include <palacios/vmm_util.h>


#define HOBBES_CPUID_LEAF 0x41000000
#define HOBBES_MAGIC      0x40bbe5
#define HOBBES_VERSION    1


static int 
hobbes_cpuid_handler(struct v3_core_info * core, 
		     uint32_t              cpuid, 
		     uint32_t            * eax, 
		     uint32_t            * ebx, 
		     uint32_t            * ecx, 
		     uint32_t            * edx, 
		     void                * priv_data) 
{
    uint32_t enclave_id = (uint32_t)(addr_t)priv_data;

    *eax = 0;                 // Don't Care (?)
    *ebx = HOBBES_MAGIC;
    *ecx = HOBBES_VERSION;
    *edx = enclave_id;

    return 0;
}



static int 
hobbes_init(struct v3_vm_info * vm, 
	    v3_cfg_tree_t     * cfg, 
	    void             ** priv_data) 
{
    char   * enclave_str = v3_cfg_val(cfg, "enclave_id");
    uint32_t enclave_id  = -1;
    

    if (enclave_str == NULL) {
	PrintError("Hobbes is enabled but no enclave ID was specified\n");
	return -1;
    }
    
    enclave_id = v3_atoi(-1, enclave_str);


    if (enclave_id == -1) {
	PrintError("Invalid config value. 'enclave_id' is not a number\n");
	return -1;
    }

    V3_Print("Enabling Hobbes Environment\n");

    v3_hook_cpuid(vm, HOBBES_CPUID_LEAF, hobbes_cpuid_handler, (void *)(addr_t)enclave_id);
			 
    return 0;
}




static struct v3_extension_impl hobbes_impl = {
    .name        = "HOBBES_ENV",
    .init        = hobbes_init,
    .deinit      = NULL,
    .core_init   = NULL,
    .core_deinit = NULL,
    .on_entry    = NULL,
    .on_exit     = NULL
};



register_extension(&hobbes_impl);
