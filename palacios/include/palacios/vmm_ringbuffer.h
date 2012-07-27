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

#ifndef __VMM_RING_BUFFER_H__
#define __VMM_RING_BUFFER_H__

#ifdef __V3VEE__

#include <palacios/vmm_types.h>


struct v3_ringbuf {
    uint8_t * buf;
    uint32_t size;

    uint32_t start;
    uint32_t end;
    uint32_t current_len;
};


void v3_init_ringbuf(struct v3_ringbuf * ring, uint32_t size);
struct v3_ringbuf * v3_create_ringbuf(uint32_t size);
void v3_free_ringbuf(struct v3_ringbuf * ring);


int v3_ringbuf_read(struct v3_ringbuf * ring, uint8_t * dst, uint32_t len);
int v3_ringbuf_peek(struct v3_ringbuf * ring, uint8_t * dst, uint32_t len);
int v3_ringbuf_delete(struct v3_ringbuf * ring, uint32_t len);
int v3_ringbuf_write(struct v3_ringbuf * ring, uint8_t * src, uint32_t len);
int v3_ringbuf_data_len(struct v3_ringbuf * ring);
int v3_ringbuf_capacity(struct v3_ringbuf * ring);
int v3_ringbuf_avail_space(struct v3_ringbuf * ring);

void v3_print_ringbuf(struct v3_ringbuf * ring);


#endif

#endif // ! __VMM_RING_BUFFER_H__
