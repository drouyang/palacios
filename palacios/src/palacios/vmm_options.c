/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2013, Patrick G. Bridges <bridges@cs.unm.edu> 
 * Copyright (c) 2013, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Patrick G. Bridges <bridges@cs.unm.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmm.h>
#include <palacios/vmm_config.h>
#include <palacios/vm_guest.h>
#include <palacios/vmm_string.h>
#include <palacios/vmm_options.h>

/* Options are space-separated values of the form "X=Y", for example
 * scheduler=EDF CPUs=1,2,3,4
 * THe following code pushes them into a hashtable for each of access
 * by other code. Storage is allocated for keys and values as part
 * of this process. XXX Need a way to deallocate this storage if the 
 * module is removed XXX
 */
static struct hashtable * option_table = NULL;
static uint8_t * string_table = NULL;
static char * true_val = "true";
 
static uint_t option_hash_fn(addr_t key) {
    char * name = (char *)key;
    return v3_hash_buffer((uint8_t *)name, strlen(name));
}

static int option_eq_fn(addr_t key1, addr_t key2) {
    char * name1 = (char *)key1;
    char * name2 = (char *)key2;

    return (strcmp(name1, name2) == 0);
}

static char * eat_whitespace(char * str) {
    while (isspace(*str)) {
	*str = 0;
	str++;
    }

    return str;
}

static char * get_end_of_word(char * str) {

    while (*str) {
	if ((*str == ',') || (*str == '=') || isspace(*str)) {
	    break;
	}
	str++;
    }

    return str;
}

int V3_init_options(char * options) {
    char * c = NULL;
    int opt_len = -1;

    if (options == NULL) {
	return 0; 
    }

    option_table = v3_create_htable(0, option_hash_fn, option_eq_fn);

    if (option_table == NULL) {
	PrintError("Error creating option table\n");
	return -1;
    }
    
    // allocate length of options + NULL terminator byte
    opt_len = strlen(options) + 1; 
    string_table = V3_Malloc(opt_len);

    if (string_table == NULL) {
	v3_free_htable(option_table, 0, 0);
	PrintError("Could not allocate option string table\n");
	return -1;
    }

    memset(string_table, 0, opt_len);
    memcpy(string_table, options, strlen(options));
    c = string_table;
    

    // Will terminate when it hits the late byte (NULL) in string table
    while (*c) {
	char * key = NULL;
	char * val = NULL;

	// set spaces to NULL
	c = eat_whitespace(c);

	key = c;

	// end of the road
	if (!*key) break;
	
	// skip the rest of the key
	c = get_end_of_word(key);
	c = eat_whitespace(c);

	// Parse the value from the rest of the string
	if ((!*c) || (*c == ',')) {
	    // No value set
	    val = true_val;
	} else {
	    // value is set (*c == '=')
	    *c = '\0';
	    c++;

	    // skip prepended whitespace
	    c = eat_whitespace(c);
	    val = c;
	    
	    // get the value
	    c = get_end_of_word(val);

	    if (c == val) {
		// Nothing was there.... 
		PrintError("Syntax error in VMM options. No value for key (%s).\n", key);
		v3_free_htable(option_table, 0, 0);
		V3_Free(string_table);
		return -1;
	    }
	}
	

	// Now Key holds the key value, and val holds the value
	// insert into hashtable
	v3_htable_insert(option_table, (addr_t)key, (addr_t)val);

	// fix up to point to start of key
	c = eat_whitespace(c);

	if (*c == ',') {
	    *c = '\0';
	    c++;
	} else if (*c) {
	    PrintError("Invalid VMM option syntax. Missing comma at end of Key/Value pair\n");
	    return -1;
	}
    }

    return 0;
}

char * v3_lookup_option(char * key) {
    return (char *)v3_htable_search(option_table, (addr_t)key);
}
