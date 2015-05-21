/*
 * (c) 2015, Charles Smith <cas275@pitt.edu>
 */

#ifndef __CONFIG_H__
#define __CONFIG_H___

#include <stdint.h>
#include <pet_xml.h>


//creates a standard config with <mem> memory and <cpu> cores
pet_xml_t v3_create_default_config(int mem_size, int num_cpus);

int  v3_set_mem_size(pet_xml_t root, uint64_t  mem_size );
int  v3_set_num_cpus(pet_xml_t root, uint32_t  num_cpus );


//returns a pet_xml_t of a device, for adding into root
pet_xml_t v3_make_device(char * id, char * class);
//adds device <device> into <root>
pet_xml_t v3_add_device(pet_xml_t root, pet_xml_t device);

//adds IDE HDD to root and returns the device xml tree
pet_xml_t v3_add_hda(pet_xml_t root, char * hd_path);
pet_xml_t v3_add_hdb(pet_xml_t root, char * hd_path);
//pet_xml_t v3_add_hdc(pet_xml_t root, char* hd_path);

//adds cd to root and returns the device XML tree
pet_xml_t v3_add_cd(pet_xml_t root, char * cd_path);

//adds vda to root and returns the device XML tree
pet_xml_t v3_add_vd(pet_xml_t root, char * vd_path);


//adds the curses console to the device list
pet_xml_t v3_add_curses(pet_xml_t root);

//disables large pages
int v3_disable_large_pages(pet_xml_t root);

//disables nested paging
int v3_disable_nested_pages(pet_xml_t root);

#endif
