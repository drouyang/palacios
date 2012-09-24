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


#include "v3_ctrl.h"



#define PRINT_TELEMETRY  0x00000001
#define PRINT_CORE_STATE 0x00000002
#define PRINT_ARCH_STATE 0x00000004
#define PRINT_STACK      0x00000008
#define PRINT_BACKTRACE  0x00000010

#define CLEAR_COUNTERS   0x40000000
#define SINGLE_EXIT_MODE 0x80000000 // begin single exit when this flag is set, until flag is cleared.


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
    int vm_fd;
    char * vm_dev = NULL;
    struct v3_debug_cmd cmd;
    int exit_mode_disable = 0;
    int c;
    int num_opts = 0;

    memset(&cmd, 0, sizeof(struct v3_debug_cmd));
    
    opterr = 0;

    while ((c = getopt(argc, argv, "tcasbS")) != -1) {
	num_opts++;

	switch (c) {
	    case 't': 
		cmd.cmd |= PRINT_TELEMETRY;
		break;
	    case 'c': 
		cmd.cmd |= PRINT_CORE_STATE;
		break;
	    case 'a': 
		cmd.cmd |= PRINT_ARCH_STATE;
		break;
	    case 's':
		cmd.cmd |= PRINT_STACK;
		break;
	    case 'b':
		cmd.cmd |= PRINT_BACKTRACE;
		break;
	    case 'C':
		cmd.cmd |= CLEAR_COUNTERS;
		break;
	    case 'S':
		cmd.cmd |= SINGLE_EXIT_MODE;
		break;
	}
    }

    printf("argc=%d, optind=%d\n", argc, optind);

    if (argc - optind + num_opts < 3) {
	usage();
	return -1;
    }


    vm_dev = argv[optind];
    cmd.core = atoi(argv[optind]);

    printf("Debug Virtual Core %d with Command %x\n", cmd.core, cmd.cmd);

    vm_fd = open(vm_dev, O_RDONLY);

    if (vm_fd == -1) {
	printf("Error opening VM device: %s\n", vm_dev);
	return -1;
    }

    int err = ioctl(vm_fd, V3_VM_DEBUG, &cmd); 

    if (err < 0) {
	printf("Error write core migrating command to vm\n");
	return -1;
    }

    close(vm_fd); 

    return 0; 
}


