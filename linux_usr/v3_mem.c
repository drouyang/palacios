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
    printf("Usage: v3_mem"   \
       " [-n, --numa=numa_zone] "   \
       " [-i --explicit] "      \
       "\n");
    exit(-1);
}

int main(int argc, char* argv[]) {
    char * mem_str = NULL;

    int explicit   =  0;
    int numa_zone  = -1;
    int num_blocks =  0;
    int ret        =  0;


    /* Parse options */
    {
	char c = 0;
	int opt_index = 0;

	static struct option long_options[] = {
	    {"numa", required_argument, 0, 'n'},
	    {"explicit", no_argument, 0, 'i'},
	     {0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "n:i:", long_options, &opt_index)) != -1) {
	    switch (c) {
	    case 'n':
		numa_zone = atoi(optarg);
		break;
	    case 'i':
		explicit = 1;
		mem_str = optarg;
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

    if (explicit) {
	char * iter_str = NULL;

	while (iter_str = strsep(&mem_str, ",")) {
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

    return 0;
}
