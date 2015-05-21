//Charles Smith <cas275@pitt.edu>
#ifndef _config_h_
#define _config_h_

#include "pet_xml.h"


//creates a standard config with <mem> memory and <cpu> cores
pet_xml_t v3_create_config(int mem, int cpu);

//adds device <device> into <root>
pet_xml_t v3_add_device(pet_xml_t root, pet_xml_t device);

//adds hda to root
pet_xml_t v3_add_hda(pet_xml_t root, char* hd_path);

//adds hdb to root
pet_xml_t v3_add_hdb(pet_xml_t root, char* hd_path);

//adds hdc to root
pet_xml_t v3_add_hdc(pet_xml_t root, char* hd_path);

//adds cd to root
pet_xml_t v3_add_cd(pet_xml_t root, char* cd_path);

//adds vda to root
pet_xml_t v3_add_vd(pet_xml_t root, char* vd_path);

//returns a pet_xml_t of a device, for adding into root
pet_xml_t v3_make_device(char* id, char* class);

//adds the curses console to the device list
pet_xml_t v3_add_curses(pet_xml_t root);

//disables large pages
void v3_disable_large_pages(pet_xml_t root);

//disables nested paging
void v3_disable_nested_pages(pet_xml_t root);

#endif
