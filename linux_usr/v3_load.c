/* 
 * V3 checkpoint save utility
 */


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <sys/ioctl.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include<linux/unistd.h>

#include "v3vee.h"
#include "v3_ioctl.h"

int main(int argc, char* argv[]) {
    int ret = 0;

    if (argc < 4) {
	printf("usage: v3_load <vm_device> <store> <url>\n");
	return -1;
    }

    {
	char * vm_dev = argv[1];
	
	ret = v3_load_vm(get_vm_id_from_path(vm_dev), argv[2], argv[3]);
	
	if (ret != 0) {
	    printf("Error: Could not load VM checkpoint (%s)\n", argv[3]);
	    return -1;
	}
    }

    return 0; 
}


