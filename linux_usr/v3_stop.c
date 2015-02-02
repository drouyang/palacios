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
 
#include "v3_ioctl.h"

int main(int argc, char* argv[]) {
    int vm_fd = 0;
    char * filename = argv[1];

    if (argc <= 1) {
	printf("usage: v3_stop <vm-device>\n");
	return -1;
    }

    printf("Stopping VM (%s)\n", filename);
    
    vm_fd = open(filename, O_RDONLY);

    if (vm_fd == -1) {
	printf("Error opening V3Vee VM device\n");
	return -1;
    }

    ioctl(vm_fd, V3_VM_STOP, NULL); 



    /* Close the file descriptor.  */ 
    close(vm_fd); 
 


    return 0; 
} 


