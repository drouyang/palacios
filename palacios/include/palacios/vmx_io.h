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
#ifndef __VMX_IO_H__
#define __VMX_IO_H__

#ifdef __V3VEE__


struct vmx_exit_info;
struct v3_core_info;
struct v3_vm_info;

int v3_init_vmx_io_map(struct v3_vm_info * vm);
int v3_deinit_vmx_io_map(struct v3_vm_info * vm);

int v3_handle_vmx_io_in(struct v3_core_info * core, struct vmx_exit_info * exit_info);
int v3_handle_vmx_io_ins(struct v3_core_info * core, struct vmx_exit_info * exit_info);
int v3_handle_vmx_io_out(struct v3_core_info * core, struct vmx_exit_info * exit_info);
int v3_handle_vmx_io_outs(struct v3_core_info * core, struct vmx_exit_info * exit_info);


#endif
#endif
