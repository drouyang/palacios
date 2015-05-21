/* Host PCI User space tool
 *  (c) Jack Lange, 2012
 *  jacklange@cs.pitt.edu 
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
#include <pet_pci.h>

void usage() {
    printf("Usage:\n"); 
    printf("\tv3_pci [<bus>:<dev>.<fn>]                  --- List PCI Device State\n");
    printf("\tv3_pci -a <name> [-f] <bus>:<dev>.<fn>     --- Add PCI Device\n");
    printf("\tv3_pci -r <name> [-f] <bus>:<dev>.<fn>     --- Remove PCI Device\n");
}


typedef enum {QUERY, ADD, REMOVE} op_mode_t;



int main(int argc, char ** argv) {
    char      * bdf_str = NULL;
    char      * name    = NULL;
    op_mode_t   mode    = QUERY;
    u8          force   = 0;


    {
	char c         = 0;
	int  opt_index = 0;

	static struct option long_options[] = {
	    {"help",   no_argument,       0, 'h'},
	    {"remove", required_argument, 0, 'r'},
	    {"add",    required_argument, 0, 'a'},
	    {"force",  no_argument,       0, 'f'},
	    {0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "r:a:fh", long_options, &opt_index)) != -1) {
	    switch (c) {
		case 'r':
		    mode = REMOVE;
		    name = optarg;
		    break;
		case 'a':
		    mode = ADD;
		    name = optarg;
		    break;
		case 'f':
		    force = 1;
		    break;
		case 'h':
		case '?':
		    usage();
		    return -1;
	    }
	}
    }

    if (mode == QUERY) {
	
	if (argc == 1) {
	    unsigned int     num_devs = 0;
	    struct pet_pci * pci_arr  = NULL;
	    int j = 0;
	    
	    if (pet_probe_pci(&num_devs, &pci_arr) != 0) {
		printf("Error: Could not probe PCI\n");
	    } else {
		printf("PCI Device States:\n");

		for (j = 0; j < num_devs; j++) {
		    printf("%.2x:%.2x.%u --  %s\n", 
			   pci_arr[j].bus, pci_arr[j].dev, pci_arr[j].fn,
			   pet_pci_state_to_str(pci_arr[j].state));
		}
	    }
	    
	} else if (argc == 2) {
	    unsigned int bus = 0;
	    unsigned int dev = 0;
	    unsigned int fn  = 0;
	    
	    bdf_str = argv[1];
	    
	    if (pet_parse_bdf(bdf_str, &bus, &dev, &fn) != 0) {
		printf("Error: Could not parse BDF spcification string\n");
		return -1;
	    }
	    
	    printf("Status=%s\n", pet_pci_state_to_str(pet_pci_status(bus, dev, fn)));
	    
	} else {
	    usage();
	    return -1;
	}
    } else if (mode == ADD)   {
	unsigned int bus = 0;
	unsigned int dev = 0;
	unsigned int fn  = 0;
	
	if (argc - optind + 1 < 2) {
	    usage();
	    return -1;
	}
	

	bdf_str = argv[optind];
	
	if (pet_parse_bdf(bdf_str, &bus, &dev, &fn) != 0) {
	    printf("Error: Could not parse BDF spcification string\n");
	    return -1;
	}
	
	if (v3_add_pci(name, bus, dev, fn, force) != 0) {
	    printf("Error: Could not add PCI device\n");
	    return -1;
	}

    } else if (mode == REMOVE) {
	unsigned int bus = 0;
	unsigned int dev = 0;
	unsigned int fn  = 0;
	
	if (argc - optind + 1 < 2) {
	    usage();
	    return -1;
	}
	
	bdf_str = argv[optind];
	
	if (pet_parse_bdf(bdf_str, &bus, &dev, &fn) != 0) {
	    printf("Error: Could not parse BDF spcification string (%s)\n", bdf_str);
	    return -1;
	}
	

	if (v3_remove_pci(name, bus, dev, fn, force) != 0) {
	    printf("Error: Could not remove pci device\n");
	    return -1;
	}
	
    } else {
	usage();
	return -1;
    }

    return 0;
}
