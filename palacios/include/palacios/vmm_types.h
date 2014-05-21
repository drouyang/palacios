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

#ifndef __VMM_TYPES_H
#define __VMM_TYPES_H

#ifdef __V3VEE__

typedef enum {SHADOW_PAGING, 
	      NESTED_PAGING}  v3_paging_mode_t;

typedef enum {VM_INVALID, 
	      VM_RUNNING, 
	      VM_STOPPED, 
	      VM_PAUSED,
	      VM_ERROR, 
	      VM_SIMULATING} v3_vm_operating_mode_t;

typedef enum {CORE_INVALID,
	      CORE_RUNNING, 
	      CORE_STOPPED} v3_core_operating_mode_t;

typedef enum {REAL, 
	      PROTECTED, 
	      PROTECTED_PAE, 
	      LONG,
	      LONG_32_COMPAT, 
	      LONG_16_COMPAT} v3_cpu_mode_t;


typedef enum {PHYSICAL_MEM, 
	      VIRTUAL_MEM} v3_mem_mode_t;


#define NULL ((void *)0)



typedef int                sint_t;
typedef unsigned int       uint_t;
typedef long               slong_t;
typedef unsigned long      ulong_t;

typedef unsigned long long uint64_t;
typedef long long          sint64_t;

typedef unsigned int       uint32_t;
typedef int                sint32_t;

typedef unsigned short     uint16_t;
typedef short              sint16_t;

typedef unsigned char      uint8_t;
typedef char               sint8_t;

#define false 0
#define true 1
typedef unsigned char      bool;
typedef unsigned long      size_t;
typedef long               ssize_t;
typedef long long          loff_t;
typedef unsigned long      addr_t;
typedef unsigned long long v3_reg_t;
#endif /* ! __V3VEE__ */


typedef struct {
    void   * iov_base;
    uint64_t iov_len;
} v3_iov_t;



#endif
