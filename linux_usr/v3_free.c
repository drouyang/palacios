/* 
 * V3 Control utility
 * (c) Jack lange, 2011
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
    unsigned long vm_idx = 0;
    int ret;


    if (argc <= 1) {
	printf("usage: v3_free <vm-dev-idx>\n");
	return -1;
    }


    vm_idx = strtol(argv[1], NULL, 0);

    printf("Freeing VM %d\n", vm_idx);
    
    vm_fd = open("/dev/v3vee", O_RDONLY);

    if (vm_fd == -1) {
	printf("Error opening V3Vee VM device\n");
	return -1;
    }

    ret = ioctl(vm_fd, V3_FREE_GUEST, vm_idx); 
    if (ret < 0) {
        printf("Error freeing VM %d\n", vm_idx);
        return -1;
    }

    /* Close the file descriptor.  */ 
    close(vm_fd); 

    return 0; 
} 


