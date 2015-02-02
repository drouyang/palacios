/* 
 * V3 Virtual Core Migrate Control
 * (c) Lei Xia, 2011
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h> 
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "v3vee.h"
#include "v3_ioctl.h"


int main(int argc, char * argv[]) {
    int ret = 0;

    if (argc < 4) {
	printf("usage: v3_core_move <vm_device> <vcore id> <target physical CPU id>\n");
	return -1;
    }

    {
	char * vm_dev = argv[1];
	int    vcore  = atoi(argv[2]);
	int    pcore  = atoi(argv[3]);
	
	printf("Migrate vcore %d to physical CPU %d\n", vcore, pcore);

	ret = v3_move_vcore(get_vm_id_from_path(vm_dev), vcore, pcore);
    }

    if (ret < 0) {
	printf("Error: Could not move core\n");
	return -1;
    }


    return 0; 
}


