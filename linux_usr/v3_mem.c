/* 
 * V3 Control utility
 * (c) Jack lange, 2010
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "v3_ioctl.h"
#include <pet_mem.h>
#include <pet_ioctl.h>


static void usage() {
    printf("Usage: v3_mem"   \
       " [-n, --numa=numa_zone] "   \
       " [-i --explicit] "      \
       "\n");
    exit(-1);
}

int main(int argc, char* argv[]) {
    int explicit = 0;
    int numa_zone = -1;
    int num_blocks = 0;

    char * mem_str = NULL;
    int ret = 0;
    struct v3_mem_region mem_range;

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

	    if (pet_offline_block(idx) == -1) {
		printf("Error: Could not offline memory block %d\n", idx);
		continue;
	    }

	    mem_range.base_addr = idx * pet_block_size();
	    mem_range.num_pages = pet_block_size() / 4096;

	    if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_MEM, &mem_range) != 0) {
		printf("Error: Could not add memory block %d to enclave\n", idx);
		continue;
	    }
	}

    } else {
	struct mem_block * block_arr = NULL;
	int cnt = atoi(mem_str);
	int i = 0;
	int ret = 0;
	int numa_num_blocks = pet_num_blocks(numa_zone);

	if (strcmp(mem_str, "all") == 0) {
	    cnt = numa_num_blocks;
	} else {
	    cnt = atoi(mem_str);
	}

	block_arr = malloc(sizeof(struct mem_block) * cnt);
	memset(block_arr, 0, sizeof(struct mem_block) * cnt);

	if (strcmp(mem_str, "all") == 0) {
	    ret = pet_offline_node(numa_zone, block_arr);
	    cnt = ret;
	} else {
	    ret = pet_offline_blocks(cnt, numa_zone, block_arr);
	}

	if (ret != cnt) {
	    printf("Error: Could not allocate %d memory blocks\n", cnt);

	    pet_online_blocks(ret, block_arr);
	    free(block_arr);

	    return -1;
	}

	for (i = 0; i < cnt; i++) {
	    mem_range.base_addr = block_arr[i].base_addr;
	    mem_range.num_pages     = block_arr[i].pages;

	    printf("Adding memory range (%p) to Palacios\n",
		   (void *)mem_range.base_addr);

	    if (pet_ioctl_path(V3_DEV_FILENAME, V3_ADD_MEM, &mem_range) != 0) {
		printf("Error: Could not add memory block %d to enclave\n", block_arr[i].base_addr / pet_block_size());
		continue;
	    }
	}

	free(block_arr);
    }

    return 0;
}
