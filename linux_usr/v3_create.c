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
#include <getopt.h> 

#include "v3vee.h"


int 
main(int argc, char ** argv)
{
    char * filename = NULL;
    char * name     = NULL;
 
    int build_flag  = 0;
    int c           = 0;

    u8 * img_data   = NULL;
    u32  img_size   = 0;

    opterr = 0;

    while (( c = getopt(argc, argv, "b")) != -1) {
	switch (c) {
	case 'b':
	    build_flag = 1;
	    break;
	}
    }

    if (argc - optind + 1 < 3) {
	printf("usage: v3_create [-b] <guest_img> <vm name>\n");
	return -1;
    }

    filename = argv[optind];
    name = argv[optind + 1];


    if (build_flag == 1) {
	ezxml_t vm_cfg = NULL;

	printf("Building VM Image (cfg=%s) (name=%s)\n", filename, name);	

	vm_cfg = v3_load_vm_cfg(filename);

	if (!vm_cfg) {
	    printf("Error: Could not load VM XML Configuration (%s)\n", filename);
	    return -1;
	}

	img_data = v3_build_vm_image(vm_cfg, &img_size);

	if (!img_data) {
	    printf("Error: Could not build VM image from configuration (%s)\n", filename);
	    return -1;
	}

    } else {
	if (v3_load_vm_image(filename, &img_data, &img_size) != 0) {
	    printf("Error: Could not load VM image (%s)\n", filename);
	    return -1;
	}
    }


    if (v3_create_vm(name, img_data, img_size) != 0) {
	printf("Error: Could not create VM (%s)\n", name);
	return -1;
    }


    return 0; 
} 

