/* 
 * V3 Control utility
 * (c) Jack lange, 2010
 */


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <sys/ioctl.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <string.h>
 
#include "v3vee.h"
#include "v3_ioctl.h"


int main(int argc, char* argv[]) {
    char * filename = argv[1];
    int ret = 0;

    if (argc <= 1) {
	printf("usage: v3_continue <vm_device>\n");
	return -1;
    }

    printf("Continuing VM (%s)\n", filename);

    ret = v3_continue_vm(get_vm_id_from_path(filename));

    if (ret < 0) {
	printf("Error: Could not continue VM\n");
	return -1;
    }

    return 0; 
} 


