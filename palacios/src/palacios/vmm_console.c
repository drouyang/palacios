/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2010, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2010, Erik van der Kouwe <vdkouwe@cs.vu.nl> 
 * Copyright (c) 2010, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 * Author: Erik van der Kouwe <vdkouwe@cs.vu.nl> 
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmm_console.h>
#include <palacios/vmm.h>
#include <palacios/vmm_debug.h>
#include <palacios/vmm_types.h>


struct v3_console_hooks * console_hooks = 0;

void V3_Init_Console(struct v3_console_hooks * hooks) {
    console_hooks = hooks;
    PrintDebug("V3 console inited\n");

    return;
}