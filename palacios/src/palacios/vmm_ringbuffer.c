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

#include <palacios/vmm_ringbuffer.h>
#include <palacios/vmm.h>




void v3_init_ringbuf(struct v3_ringbuf * ring, uint32_t size) {
    ring->buf = V3_Malloc(size);

    if (!(ring->buf)) {
	PrintError("Cannot init a ring buffer\n");
	return;
    }

    ring->size = size;
  
    ring->start = 0;
    ring->end = 0;
    ring->current_len = 0;
}

struct v3_ringbuf * v3_create_ringbuf(uint32_t size) {
    struct v3_ringbuf * ring = (struct v3_ringbuf *)V3_Malloc(sizeof(struct v3_ringbuf));

    if (!ring) {
	PrintError("Cannot allocate a ring buffer\n");
	return NULL;
    }

    v3_init_ringbuf(ring, size);

    return ring;
}


void v3_free_ringbuf(struct v3_ringbuf * ring) {
    V3_Free(ring->buf);
    V3_Free(ring);
}



static inline uint8_t * get_read_ptr(struct v3_ringbuf * ring) {
    return (uint8_t *)(ring->buf + ring->start);
}


static inline uint8_t * get_write_ptr(struct v3_ringbuf * ring) {
    return (uint8_t *)(ring->buf + ring->end);
}


static inline int get_read_section_size(struct v3_ringbuf * ring) {
    return ring->size - ring->start;
}


static inline int get_write_section_size(struct v3_ringbuf * ring) {
    return ring->size - ring->end;
}


static inline int is_read_loop(struct v3_ringbuf * ring, uint32_t len) {
    if ((ring->start >= ring->end) && (ring->current_len > 0)) {
	// end is past the end of the buffer
	if (get_read_section_size(ring) < len) {
	    return 1;
	}
    }
    return 0;
}


static inline int is_write_loop(struct v3_ringbuf * ring, uint32_t len) {
    if ((ring->end >= ring->start) && (ring->current_len < ring->size)) {
	// end is past the end of the buffer
	if (get_write_section_size(ring) < len) {
	    return 1;
	}
    }
    return 0;
}


int v3_ringbuf_avail_space(struct v3_ringbuf * ring) {
    return ring->size - ring->current_len;
}


int v3_ringbuf_data_len(struct v3_ringbuf * ring) {
    return ring->current_len;
}


int v3_ringbuf_capacity(struct v3_ringbuf * ring) {
    return ring->size;
}


int v3_ringbuf_read(struct v3_ringbuf * ring, uint8_t * dst, uint32_t len) {
    int read_len = 0;
    int ring_data_len = ring->current_len;

    read_len = (len > ring_data_len) ? ring_data_len : len;

    if (is_read_loop(ring, read_len)) {
	int section_len = get_read_section_size(ring);

	memcpy(dst, get_read_ptr(ring), section_len);
	memcpy(dst + section_len, ring->buf, read_len - section_len);
    
	ring->start = read_len - section_len;
    } else {
	memcpy(dst, get_read_ptr(ring), read_len);
    
	ring->start += read_len;
    }

    ring->current_len -= read_len;

    return read_len;
}



int v3_ringbuf_peek(struct v3_ringbuf * ring, uint8_t * dst, uint32_t len) {
    int read_len = 0;
    int ring_data_len = ring->current_len;

    read_len = (len > ring_data_len) ? ring_data_len : len;

    if (is_read_loop(ring, read_len)) {
	int section_len = get_read_section_size(ring);

	memcpy(dst, get_read_ptr(ring), section_len);
	memcpy(dst + section_len, ring->buf, read_len - section_len);
    } else {
	memcpy(dst, get_read_ptr(ring), read_len);
    }

    return read_len;
}



int v3_ringbuf_delete(struct v3_ringbuf * ring, uint32_t len) {
    int del_len = 0;
    int ring_data_len = ring->current_len;

    del_len = (len > ring_data_len) ? ring_data_len : len;

    if (is_read_loop(ring, del_len)) {
	int section_len = get_read_section_size(ring);
	ring->start = del_len - section_len;
    } else {
	ring->start += del_len;
    }

    ring->current_len -= del_len;
    return del_len;
}



int v3_ringbuf_write(struct v3_ringbuf * ring, uint8_t * src, uint32_t len) {
    int write_len = 0;
    int ring_avail_space = ring->size - ring->current_len;
  
    write_len = (len > ring_avail_space) ? ring_avail_space : len;


    if (is_write_loop(ring, write_len)) {
	int section_len = get_write_section_size(ring);

	//  PrintDebug("Write loop: write_ptr=%p, src=%p, sec_len=%d\n", 
	//	       (void *)get_write_ptr(ring),(void*)src, section_len);
    
	memcpy(get_write_ptr(ring), src, section_len);
	ring->end = 0;

	memcpy(get_write_ptr(ring), src + section_len, write_len - section_len);

	ring->end += write_len - section_len;
    } else {
	//    PrintDebug("Writing: write_ptr=%p, src=%p, write_len=%d\n", 
	//	       (void *)get_write_ptr(ring),(void*)src, write_len);

	memcpy(get_write_ptr(ring), src, write_len);

	ring->end += write_len;
    }

    ring->current_len += write_len;

    return write_len;
}



void v3_print_ringbuf(struct v3_ringbuf * ring) {
    int ctr = 0;
  
    for (ctr = 0; ctr < ring->current_len; ctr++) {
	int index = (ctr + ring->start) % ring->size;

	PrintDebug("Entry %d (index=%d): %c\n", ctr, index, ring->buf[index]);
    }
}
