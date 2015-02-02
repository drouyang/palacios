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
#include "v3vee.h"


int main(int argc, char* argv[]) {
    char * filename = argv[1];
    u32    msecs    = atoi(argv[2]);
    int    ret      = 0;
    

    if (argc <= 2) {
	printf("usage: v3_simulate <vm-dev> <msecs>\n");
	return -1;
    }

    printf("Simulating VM for %lu msecs\n", msecs);
    
    ret = v3_simulate_vm(get_vm_id_from_path(filename), msecs);

    if (ret < 0) {
        printf("Error: Could not simulate VM\n");
        return -1;
    }

    return 0; 
} 


