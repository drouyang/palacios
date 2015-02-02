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
 
#include "v3vee.h"

int main(int argc, char* argv[]) {

    unsigned long vm_idx = 0;
    int ret = 0;

    if (argc <= 1) {
	printf("usage: v3_free <vm-dev-idx>\n");
	return -1;
    }


    vm_idx = strtol(argv[1], NULL, 0);

    printf("Freeing VM %d\n", vm_idx);


    ret = v3_free_vm(vm_idx); 

    if (ret < 0) {
        printf("Error freeing VM %d\n", vm_idx);
        return -1;
    }



    return 0; 
} 


