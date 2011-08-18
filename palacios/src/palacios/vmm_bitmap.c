/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2011, Jack Lange <jacklange@cs.pitt.edu> 
 * Copyright (c) 2011, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm_bitmap.h>
#include <palacios/vmm.h>


int v3_bitmap_init(struct v3_bitmap * bitmap, int num_bits) {
    int num_bytes = (num_bits / 8) + ((num_bits % 8) > 0);

    bitmap->num_bits = num_bits;
    bitmap->bits = V3_Malloc(num_bytes);

    if (bitmap->bits == NULL) {
	PrintError("Could not allocate bitmap of %d bits\n", num_bits);
	return -1;
    }
    
    memset(bitmap->bits, 0, num_bytes);

    return 0;
}


void v3_bitmap_deinit(struct v3_bitmap * bitmap) {
    V3_Free(bitmap->bits);
}


int v3_bitmap_reset(struct v3_bitmap * bitmap) {
    int num_bytes = (bitmap->num_bits / 8) + ((bitmap->num_bits % 8) > 0);

    memset(bitmap->bits, 0, num_bytes);

    return 0;
}

int v3_bitmap_set(struct v3_bitmap * bitmap, int index) {
    int major = index / 8;
    int minor = index % 8;
    int old_val = 0;

    if (index > (bitmap->num_bits - 1)) {
	PrintError("Index out of bitmap range: (pos = %d) (num_bits = %d)\n", 
		   index, bitmap->num_bits);
	return -1;
    }

    old_val = (bitmap->bits[major] & (0x1 << minor));
    bitmap->bits[major] |= (0x1 << minor);

    return old_val;
}


int v3_bitmap_clear(struct v3_bitmap * bitmap, int index) {
    int major = index / 8;
    int minor = index % 8;
    int old_val = 0;

    if (index > (bitmap->num_bits - 1)) {
	PrintError("Index out of bitmap range: (pos = %d) (num_bits = %d)\n", 
		   index, bitmap->num_bits);
	return -1;
    }

    old_val = (bitmap->bits[major] & (0x1 << minor));
    bitmap->bits[major] &= ~(0x1 << minor);

    return old_val;
}

int v3_bitmap_check(struct v3_bitmap * bitmap, int index) {
    int major = index / 8;
    int minor = index % 8;

    if (index > (bitmap->num_bits - 1)) {
	PrintError("Index out of bitmap range: (pos = %d) (num_bits = %d)\n", 
		   index, bitmap->num_bits);
	return -1;
    }

    return (bitmap->bits[major] & (0x1 << minor));
}

