/* 
 * V3 Control utility
 * (c) Jack lange, 2010
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include "v3_ioctl.h"
#include "v3vee.h"

int main(int argc, char* argv[]) {
    char * filename = argv[1];
    int ret = 0;

    if (argc <= 1) {
	printf("usage: v3_stop <vm-device>\n");
	return -1;
    }

    printf("Stopping VM (%s)\n", filename);
    
    
    ret = v3_stop_vm(get_vm_id_from_path(filename));

    if (ret < 0) {
        printf("Error: Could not stop VM\n");
        return -1;
    }


    return 0; 
} 


