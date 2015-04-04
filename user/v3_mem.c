/* 
 * V3 Control utility
 * (c) Jack lange, 2010
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "v3vee.h"


static void usage() {
    printf("Usage: v3_mem [-r] <num_blocks>"   \
	   " [-n, --numa=numa_zone] "	  \
	   " [-i --explicit=<blocks>] "	  \
	   "\n");
    exit(-1);
}

int main(int argc, char* argv[]) {
    char * mem_str = NULL;

    int explicit   =  0;
    int numa_zone  = -1;
    int remove     =  0;
    int ret        =  0;

    /* Parse options */
    {
	char c = 0;
	int opt_index = 0;

	static struct option long_options[] = {
	    {"numa",     required_argument, 0, 'n'},
	    {"explicit", no_argument,       0, 'i'},
	    {"remove",   no_argument,       0, 'r'},
	     {0, 0, 0, 0}
	};
	
	while ((c = getopt_long(argc, argv, "n:i:r", long_options, &opt_index)) != -1) {
	    switch (c) {
		case 'n':
		    numa_zone = atoi(optarg);
		    break;
		case 'i':
		    explicit = 1;
		    mem_str = optarg;
		    break;
		case 'r':
		    remove = 1;
		    break;
		case '?':
		    usage();
		    break;
	    }
	}

	//if (optind + 1 != argc) {
	if ((!explicit) && (argc - optind + 1 < 2)) {
	    usage();
	    return -1;
	}
    }
    
    mem_str = argv[optind];

    if (remove == 0) {
	if (explicit) {
	    char * iter_str = NULL;
	    
	    while ((iter_str = strsep(&mem_str, ","))) {
		int idx = atoi(iter_str);
		
		if (v3_add_mem_explicit(idx) != 0) {
		    printf("Error: Could not add memory block %d to Palacios\n", idx);
		    continue;
		}
	    }
	    
	} else {
	    
	    if (strcmp(mem_str, "all") == 0) {
		ret = v3_add_mem_node(numa_zone);
	    } else {
		int cnt = atoi(mem_str);
		ret = v3_add_mem(cnt, numa_zone);
	    }
	}
    } else {
	
	int cnt = atoi(mem_str);
	v3_remove_mem(cnt, numa_zone);
    }


    return ret;
}
