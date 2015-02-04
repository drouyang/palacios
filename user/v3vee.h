/* 
 * V3vee User control header file
 * (c) 2015, Jack Lange <jacklange@cs.pitt.edu>
 */

#ifndef __V3VEE_H__
#define __V3VEE_H__

#include "v3_types.h"
#include <ezxml.h>



int v3_add_cpu(int cpu_id);
int v3_remove_cpu(int cpu_id);


int v3_add_mem_node(int numa_zone);
int v3_add_mem(int num_blocks, 
	       int numa_zone);
int v3_add_mem_explicit(int block_id);





int v3_create_vm(char * vm_name, u8 * img_data, u32 img_size);

int v3_load_vm_image(char  * file_name,
		     u8   ** img_data,
		     u32   * img_size);

int v3_save_vm_image(char * file_name, 
		     u8   * img_data,
		     u32    img_size);


ezxml_t v3_load_vm_cfg(char * file_name);
int     v3_save_vm_cfg(char * file_name, ezxml_t vm_xml_cfg);


u8 * v3_build_vm_image(ezxml_t   vm_xml_cfg, 
		       u32     * img_size);


int v3_save_vm(int    vm_id,
	       char * store,
	       char * url);

int v3_load_vm(int    vm_id,
	       char * store,
	       char * url);

int v3_free_vm(int vm_id);


int v3_launch_vm(int vm_id);
int v3_stop_vm(int vm_id);

int v3_continue_vm(int vm_id);
int v3_pause_vm(int vm_id);
int v3_simulate_vm(int vm_id, u32 msecs);

int v3_move_vcore(int vm_id,
		  int vcore,
		  int target_pcore);



#define PRINT_TELEMETRY  0x00000001
#define PRINT_CORE_STATE 0x00000002
#define PRINT_ARCH_STATE 0x00000004
#define PRINT_STACK      0x00000008
#define PRINT_BACKTRACE  0x00000010

#define CLEAR_COUNTERS   0x40000000
#define SINGLE_EXIT_MODE 0x80000000 // begin single exit when this flag is set, until flag is cleared.
int v3_debug_vm(int vm_id, u32 core, u32 flags);



#endif
