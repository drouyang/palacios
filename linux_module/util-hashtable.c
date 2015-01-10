/*
  Copyright (c) 2002, 2004, Christopher Clark
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  
  * Neither the name of the original author; nor the names of any contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
  
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <linux/string.h>
#include <linux/errno.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "palacios.h" 
#include "util-hashtable.h"
#include "mm.h"


struct hash_entry {
    uintptr_t key;
    uintptr_t value;
    u32       hash;
    struct hash_entry * next;
};

struct hashtable {
    u32 table_length;
    struct hash_entry ** table;
    u32 entry_count;
    u32 load_limit;
    u32 prime_index;
    u32 (*hash_fn)(uintptr_t key);
    int (*eq_fn)  (uintptr_t key1, uintptr_t key2);
};


/* HASH FUNCTIONS */

static inline u32 do_hash(struct hashtable * htable, uintptr_t key) {
    /* Aim to protect against poor hash functions by adding logic here
     * - logic taken from java 1.4 hashtable source */
    u32 i = htable->hash_fn(key);

    i +=  ~(i << 9);
    i ^=  ((i >> 14) | (i << 18)); /* >>> */
    i +=   (i << 4);
    i ^=  ((i >> 10) | (i << 22)); /* >>> */

    return i;
}


u32 
palacios_hash_ptr(uintptr_t val) {
    uintptr_t hash = val;
    uintptr_t n    = hash;

    /*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
    n    <<= 18;
    hash  -= n;
    n    <<= 33;
    hash  -= n;
    n    <<= 3;
    hash  += n;
    n    <<= 3;
    hash  -= n;
    n    <<= 4;
    hash  += n;
    n    <<= 2;
    hash  += n;

    /* High bits are more random, so use them. */
    return (u32)(hash >> 32);
}

/* HASH GENERIC MEMORY BUFFER */
/* ELF HEADER HASH FUNCTION */
u32
palacios_hash_buffer(u8 * msg,
		     u32  length)
{
    u32 hash = 0;
    u32 temp = 0;
    u32 i;

    for (i = 0; i < length; i++) {
	hash  = (hash << 4) + *(msg + i) + i;

	if ((temp = (hash & 0xF0000000))) {
	    hash ^= (temp >> 24);
	}

	hash &= ~temp;
    }
    return hash;
}

/* indexFor */
static inline u32 indexFor(u32 table_length, u32 hash_value) {
    return (hash_value % table_length);
};

#define freekey(X) palacios_kfree(X)


static void * 
tmp_realloc(void * old_ptr,
	    u32    old_size, 
	    u32    new_size)
{
    void * new_buf = palacios_kmalloc(new_size, GFP_KERNEL);

    if (new_buf == NULL) {
	return NULL;
    }

    memcpy(new_buf, old_ptr, old_size);
    palacios_kfree(old_ptr);

    return new_buf;
}


/*
  Credit for primes table: Aaron Krowne
  http://br.endernet.org/~akrowne/
  http://planetmath.org/encyclopedia/GoodHashTablePrimes.html
*/
static const u32 primes[] = { 
    53, 97, 193, 389,
    769, 1543, 3079, 6151,
    12289, 24593, 49157, 98317,
    196613, 393241, 786433, 1572869,
    3145739, 6291469, 12582917, 25165843,
    50331653, 100663319, 201326611, 402653189,
    805306457, 1610612741 };


// this assumes that the max load factor is .65
static const u32 load_factors[] = {
    35, 64, 126, 253,
    500, 1003, 2002, 3999,
    7988, 15986, 31953, 63907,
    127799, 255607, 511182, 1022365,
    2044731, 4089455, 8178897, 16357798,
    32715575, 65431158, 130862298, 261724573,
    523449198, 1046898282 };

const u32 prime_table_len = sizeof(primes) / sizeof(primes[0]);

struct hashtable * 
palacios_create_htable(u32 min_size,
		       u32 (*hash_fn)(uintptr_t),
		       int (*eq_fn)  (uintptr_t, uintptr_t)) 
{
    struct hashtable * htable = NULL;
    u32 prime_index           = 0;
    u32 size                  = primes[0];

    /* Check requested hashtable isn't too large */
    if (min_size > (1u << 30)) {
	return NULL;
    }

    /* Enforce size as prime */
    for (prime_index = 0; prime_index < prime_table_len; prime_index++) {
        if (primes[prime_index] > min_size) { 
	    size = primes[prime_index]; 
	    break; 
	}
    }

    htable = (struct hashtable *)palacios_kmalloc(sizeof(struct hashtable), GFP_KERNEL);

    if (htable == NULL) {
	return NULL; /*oom*/
    }

    htable->table = (struct hash_entry **)palacios_kmalloc(sizeof(struct hash_entry*) * size, GFP_KERNEL);

    if (htable->table == NULL) { 
	palacios_kfree(htable); 
	return NULL;  /*oom*/
    }

    memset(htable->table, 0, size * sizeof(struct hash_entry *));

    htable->table_length  = size;
    htable->prime_index   = prime_index;
    htable->entry_count   = 0;
    htable->hash_fn       = hash_fn;
    htable->eq_fn         = eq_fn;
    htable->load_limit    = load_factors[prime_index];

    return htable;
}


static int
hashtable_expand(struct hashtable * htable) 
{
    /* Double the size of the table to accomodate more entries */
    struct hash_entry ** new_table = NULL;
    struct hash_entry  * tmp_entry = NULL;
    struct hash_entry ** entry_ptr = NULL;

    u32 new_size = 0;
    u32 index    = 0;
    u32 i        = 0;

    /* Check we're not hitting max capacity */
    if (htable->prime_index == (prime_table_len - 1)) {
	return 0;
    }

    new_size  = primes[++(htable->prime_index)];

    new_table = (struct hash_entry **)palacios_kmalloc(sizeof(struct hash_entry*) * new_size, GFP_KERNEL);

    if (new_table != NULL) {
        memset(new_table, 0, new_size * sizeof(struct hash_entry *));
        /* This algorithm is not 'stable'. ie. it reverses the list
         * when it transfers entries between the tables */

        for (i = 0; i < htable->table_length; i++) {

	    while ((tmp_entry = htable->table[i]) != NULL) {
		htable->table[i] = tmp_entry->next;
		index            = indexFor(new_size, tmp_entry->hash);
		tmp_entry->next  = new_table[index];
		new_table[index] = tmp_entry;
	    }
        }

        palacios_kfree(htable->table);

        htable->table = new_table;
    } else {
	/* Plan B: realloc instead */

	//new_table = (struct hash_entry **)realloc(htable->table, new_size * sizeof(struct hash_entry *));
	new_table = (struct hash_entry **)tmp_realloc(htable->table, 
						      primes[htable->prime_index - 1], 
						      new_size * sizeof(struct hash_entry *));

	if (new_table == NULL) {
	    (htable->prime_index)--;
	    return 0;
	}

	htable->table = new_table;

	memset(new_table[htable->table_length], 0, new_size - htable->table_length);

	for (i = 0; i < htable->table_length; i++) {

	    entry_ptr  = &(new_table[i]);

	    for (tmp_entry  = *entry_ptr; 
		 tmp_entry != NULL; 
		 tmp_entry  = *entry_ptr) {

		index = indexFor(new_size, tmp_entry->hash);

		if (i == index) {
		    entry_ptr        = &(tmp_entry->next);
		} else {
		    *entry_ptr       = tmp_entry->next;
		    tmp_entry->next  = new_table[index];
		    new_table[index] = tmp_entry;
		}
	    }
	}
    }

    htable->table_length = new_size;

    htable->load_limit   = load_factors[htable->prime_index];

    return -1;
}

u32 
palacios_htable_count(struct hashtable * htable) 
{
    return htable->entry_count;
}

int 
palacios_htable_insert(struct hashtable * htable,
		       uintptr_t          key, 
		       uintptr_t          value) 
{
    /* This method allows duplicate keys - but they shouldn't be used */
    struct hash_entry * new_entry = NULL;
    u32 index                     = 0;

    if (++(htable->entry_count) > htable->load_limit) {
	/* Ignore the return value. If expand fails, we should
	 * still try cramming just this value into the existing table
	 * -- we may not have memory for a larger table, but one more
	 * element may be ok. Next time we insert, we'll try expanding again.*/
	hashtable_expand(htable);
    }

    new_entry = (struct hash_entry *)palacios_kmalloc(sizeof(struct hash_entry), GFP_KERNEL);

    if (new_entry == NULL) { 
	(htable->entry_count)--; 
	return 0; /*oom*/
    }

    new_entry->hash      = do_hash(htable, key);
    index                = indexFor(htable->table_length, new_entry->hash);

    new_entry->key       = key;
    new_entry->value     = value;

    new_entry->next      = htable->table[index];
    htable->table[index] = new_entry;

    return -1;
}


int 
palacios_htable_change(struct hashtable * htable, 
		       uintptr_t          key, 
		       uintptr_t          value, 
		       int                free_value) 
{
    struct hash_entry * tmp_entry = NULL;
    u32 hash_value                = 0;
    u32 index                     = 0;

    hash_value = do_hash(htable, key);
    index      = indexFor(htable->table_length, hash_value);
    tmp_entry  = htable->table[index];

    while (tmp_entry != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ( (hash_value == tmp_entry->hash) && 
	     (htable->eq_fn(key, tmp_entry->key)) ) {

	    if (free_value) {
		palacios_kfree((void *)(tmp_entry->value));
	    }

	    tmp_entry->value = value;
	    return -1;
        }

        tmp_entry = tmp_entry->next;
    }
    return 0;
}



int 
palacios_htable_inc(struct hashtable * htable, 
		    uintptr_t          key,
		    uintptr_t          value) 
{
    struct hash_entry * tmp_entry = NULL;
    u32 hash_value = 0;
    u32 index      = 0;

    hash_value = do_hash(htable, key);
    index      = indexFor(htable->table_length, hash_value);
    tmp_entry  = htable->table[index];

    while (tmp_entry != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ( (hash_value == tmp_entry->hash) && 
	     (htable->eq_fn(key, tmp_entry->key)) ) {

	    tmp_entry->value += value;
	    return -1;
        }

        tmp_entry = tmp_entry->next;
    }
    return 0;
}


int 
palacios_htable_dec(struct hashtable * htable, 
		    uintptr_t          key,
		    uintptr_t          value) 
{
    struct hash_entry * tmp_entry = NULL;
    u32 hash_value  = 0;
    u32 index       = 0;

    hash_value = do_hash(htable, key);
    index      = indexFor(htable->table_length, hash_value);
    tmp_entry  = htable->table[index];

    while (tmp_entry != NULL) {
        /* Check hash value to short circuit heavier comparison */
        if ( (hash_value == tmp_entry->hash) && 
	     (htable->eq_fn(key, tmp_entry->key)) ) {

	    tmp_entry->value -= value;
	    return -1;
        }

        tmp_entry = tmp_entry->next;
    }
    return 0;
}


/* returns value associated with key */
uintptr_t
palacios_htable_search(struct hashtable * htable, 
		       uintptr_t          key) 
{
    struct hash_entry * cursor = NULL;
    u32 hash_value = 0;
    u32 index      = 0;
  
    hash_value = do_hash(htable, key);
    index      = indexFor(htable->table_length, hash_value);
    cursor     = htable->table[index];
  
    while (cursor != NULL) {
	/* Check hash value to short circuit heavier comparison */
	if ( (hash_value == cursor->hash) && 
	     (htable->eq_fn(key, cursor->key)) ) {

	    return cursor->value;
	}
    
	cursor = cursor->next;
    }
  
    return (uintptr_t)NULL;
}


/* returns value associated with key */
uintptr_t 
palacios_htable_remove(struct hashtable * htable, 
		       uintptr_t          key, 
		       int                free_key) 
{
    /* TODO: consider compacting the table when the load factor drops enough,
     *       or provide a 'compact' method. */
  
    struct hash_entry  * cursor    = NULL;
    struct hash_entry ** entry_ptr = NULL;
    uintptr_t value = 0;
    u32 hash_value  = 0;
    u32 index       = 0;
  
    hash_value = do_hash(htable, key);
    index      = indexFor(htable->table_length, hash_value);
    entry_ptr  = &(htable->table[index]);
    cursor     = *entry_ptr;

    while (cursor != NULL) {

	/* Check hash value to short circuit heavier comparison */
	if ( (hash_value == cursor->hash) && 
	     (htable->eq_fn(key, cursor->key)) ) {
     
	    *entry_ptr           = cursor->next;
	    htable->entry_count -= 1;
	    value                = cursor->value;
      
	    if (free_key) {
		freekey((void *)(cursor->key));
	    }

	    palacios_kfree(cursor);
      
	    return value;
	}

	entry_ptr = &(cursor->next);
	cursor    = cursor->next;
    }

    return (uintptr_t)NULL;
}


/* destroy */
void 
palacios_free_htable(struct hashtable * htable,
		     int                free_values,
		     int                free_keys) 
{
    struct hash_entry  * cursor = NULL;
    struct hash_entry  * tmp    = NULL;
    struct hash_entry ** table  = htable->table;
    u32 i = 0;

    if (free_values) {

	for (i = 0; i < htable->table_length; i++) {
	    cursor = table[i];
      
	    while (cursor != NULL) { 
		tmp    = cursor; 
		cursor = cursor->next; 

		if (free_keys) {
		    freekey((void *)(tmp->key)); 
		}

		palacios_kfree((void *)(tmp->value)); 
		palacios_kfree(tmp); 
	    }
	}

    } else {

	for (i = 0; i < htable->table_length; i++) {
	    cursor = table[i];

	    while (cursor != NULL) { 
		struct hash_entry * tmp = NULL;

		tmp    = cursor; 
		cursor = cursor->next; 
	
		if (free_keys) {
		    freekey((void *)(tmp->key)); 
		}

		palacios_kfree(tmp); 
	    }
	}
    }
  
    palacios_kfree(htable->table);
    palacios_kfree(htable);
}

