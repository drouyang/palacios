/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2014, Brian Kocoloski <briankoco@cs.pitt.edu> 
 * Copyright (c) 2014, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __DEVICES_XPMEM_H__
#define __DEVICES_XPMEM_H__

#ifdef __V3VEE__

#include <palacios/vmm_list.h>
#include <palacios/vmm_types.h>


int v3_xpmem_command(struct v3_xpmem_state * v3_xpmem, struct xpmem_cmd * cmd);

#endif // ! __V3VEE__


#endif

