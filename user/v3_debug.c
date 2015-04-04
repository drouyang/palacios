/* 
 * V3 debug interface
 * (c) Jack Lange, 2012
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h> 
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


#include "v3_ioctl.h"
#include "v3vee.h"


void usage() {

	printf("usage: v3_debug <flags> <vm_device> <vm core>\n");
	printf("\t-t: Print telemetry\n");
	printf("\t-c: Print Core State\n");
	printf("\t-a: Print Architecture State\n");
	printf("\t-s: Print Stack Trace\n");
	printf("\t-b: Print Backtrace\n");
	printf("\n");
	printf("\t-C: Clear counters\n");
	printf("\t-S: Enable single exit mode\n");
	return;

}


int main(int argc, char ** argv  ) {
    char * vm_dev = NULL;

    int num_opts = 0;
    u32 flags    = 0;
    u32 core     = 0;
    int c        = 0;

    
    opterr = 0;

    while ((c = getopt(argc, argv, "tcasbS")) != -1) {
	num_opts++;

	switch (c) {
	    case 't': 
		flags |= PRINT_TELEMETRY;
		break;
	    case 'c': 
		flags |= PRINT_CORE_STATE;
		break;
	    case 'a': 
		flags |= PRINT_ARCH_STATE;
		break;
	    case 's':
		flags |= PRINT_STACK;
		break;
	    case 'b':
		flags |= PRINT_BACKTRACE;
		break;
	    case 'C':
		flags |= CLEAR_COUNTERS;
		break;
	    case 'S':
		flags |= SINGLE_EXIT_MODE;
		break;
	}
    }

    printf("argc=%d, optind=%d\n", argc, optind);

    if (argc - optind + num_opts < 3) {
	usage();
	return -1;
    }

    vm_dev = argv[optind];
    core   = atoi(argv[optind - 1]); // No, the reversed argument ordering doesn't make sense...

    printf("Debug Virtual Core %d with Command %x\n", core, flags);

    if (v3_debug_vm(get_vm_id_from_path(vm_dev), core, flags) != 0) {
	printf("Error: Could not issue debug command to VM\n");
	return -1;
    }

    return 0; 
}


