/* CPU dynamic add/remove utility
 *  (c) Jack Lange, 2014
 *  jacklange@cs.pitt.edu 
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <sys/ioctl.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <string.h>
#include <getopt.h>


#include "v3vee.h"


static void usage() {
    printf("Usage: ./v3_cpu [-r] <cpu_id>\n");
    exit(-1);
}


int main(int argc, char ** argv) {
    int remove =  0;
    int cpu_id = -1;
    int ret    =  0;

    {
	char c = 0;
	int opt_index = 0;

	static struct option long_options[] = {
	    {"remove", no_argument, 0, 'r'},
	     {0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "r", long_options, &opt_index)) != -1) {
	    switch (c) {
	    case 'r':
		remove = 1;
		break;
	    case '?':
		usage();
		break;
	    }
	}

	//if (optind + 1 != argc) {
	if ((argc - optind + 1 < 2)) {
	    usage();
	    return -1;
	}
    }

    cpu_id = atoi(argv[optind]);

    if (remove) {
	printf("Removing CPU %d from Palacios\n", cpu_id);
	v3_remove_cpu(cpu_id);
    } else {
	printf("Addign CPU %d to Palacios\n", cpu_id);
	v3_add_cpu(cpu_id);
    }
    
}
