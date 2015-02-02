/* 
 * V3vee User control header file
 * (c) 2015, Jack Lange <jacklange@cs.pitt.edu>
 */

#ifndef __V3VEE_H__
#define __V3VEE_H__

#include "v3_types.h"
#include <ezxml.h>

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



#endif
