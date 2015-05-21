/* xml config
 * (c) 2015, Charles Smith <cas275@pitt.edu>
 */
#include <string.h>

#include <pet_xml.h>
#include <ezxml.h>  /* TODO: Remove EZXML dependencies and go through pet_xml API */

#include "config.h"



pet_xml_t 
v3_create_default_config(int  mem_size, int  num_cpus)
{
  pet_xml_t    root         = NULL;
  pet_xml_t    apic         = NULL;
  pet_xml_t    keyboard     = NULL;
  pet_xml_t    pit          = NULL;
  pet_xml_t    ioapic       = NULL;
  pet_xml_t    pci          = NULL;
  pet_xml_t    northbridge  = NULL;
  pet_xml_t    southbridge  = NULL; 
  pet_xml_t    nvram        = NULL;
  
  
  root = pet_xml_new_tree("vm");
  pet_xml_add_val(root, "class", "PC");


  v3_set_mem_size(root,  mem_size);


  /* sets the paging to the defaults */
  {
    pet_xml_t page = NULL;
    
    page = pet_xml_new_tree("paging");
    
    pet_xml_add_val(page, "mode", "nested");
    pet_xml_add_val(page, "large_pages", "true");
    
    ezxml_insert(page, root, 0); 
  }


  pet_xml_add_val(root, "schedule_hz", "100");


  v3_set_num_cpus(root,  num_cpus  );


  pet_xml_add_subtree(root, "devices");


  apic        = v3_make_device("LAPIC"   , "apic"         );
  keyboard    = v3_make_device("KEYBOARD", "keyboard"     );
  pit         = v3_make_device("8254_PIT", "PIT"          );
  ioapic      = v3_make_device("IOAPIC"  , "ioapic"       );
  pci         = v3_make_device("PCI"     , "pci0"         );
  northbridge = v3_make_device("i440FX"  , "northbridge"  );
  southbridge = v3_make_device("PIIX3"   , "southbridge"  );
  nvram       = v3_make_device("NVRAM"   , "nvram"        );

  
  pet_xml_add_val(ioapic     , "apic"   , "apic");
  pet_xml_add_val(northbridge, "bus"    , "pci0");
  pet_xml_add_val(southbridge, "bus"    , "pci0");
  pet_xml_add_val(nvram      , "storage", "ide" );
  
  

  v3_add_device( root , apic        );
  v3_add_device( root , keyboard    );
  v3_add_device( root , pit         );
  v3_add_device( root , ioapic      );
  v3_add_device( root , pci         );
  v3_add_device( root , northbridge );
  v3_add_device( root , southbridge );

  /* Add IDE device with special tags */
  {
    pet_xml_t ide = NULL;
    
    ide = v3_make_device("IDE", "ide");
    
    pet_xml_add_val(ide , "bus"        , "pci0"       );
    pet_xml_add_val(ide , "controller" , "southbridge");
    
    v3_add_device(root, ide);

  }

  v3_add_device( root , nvram);

  return root;
}


pet_xml_t
v3_add_device(pet_xml_t root, pet_xml_t device)
{
  pet_xml_t devices = NULL;

  devices = pet_xml_get_subtree(root, "devices");
  ezxml_insert(device, devices, 0);
  
  
  return root;
}


static pet_xml_t
add_ide(pet_xml_t   root,
	char      * file_path,
	char      * id,
	uint8_t     writable,
	uint8_t     bus_num,
	uint8_t     drive_num,
	uint8_t     is_cdrom)
{
  pet_xml_t dev      = NULL;
  pet_xml_t frontend = NULL;

  char * bus_str = NULL;
  char * drv_str = NULL;

  dev = v3_make_device("FILEDISK", id);

  frontend = pet_xml_add_subtree(dev, "frontend");
  
  pet_xml_add_val(dev,      "writable", ((writable == 1) ? "1" : "0")  );
  pet_xml_add_val(dev,      "path"    , file_path   );
  pet_xml_add_val(frontend, "tag"     , "ide"     );

  if ( is_cdrom ) {
      pet_xml_add_val(frontend, "model" , "V3Vee CDROM");
      pet_xml_add_val(frontend, "type"  , "CDROM"      );
  } else {
      pet_xml_add_val(frontend, "model" , "V3Vee HDD");
      pet_xml_add_val(frontend, "type"  , "HD" );    
  }

  asprintf(&bus_str, "%u", bus_num);
  asprintf(&drv_str, "%u", drive_num);
  
  pet_xml_add_val(frontend, "bus_num"  , bus_str );
  pet_xml_add_val(frontend, "drive_num", drv_str );
  
  free(bus_str);
  free(drv_str);
    
  v3_add_device(root, dev);

  return dev;
}


pet_xml_t
v3_add_hda(pet_xml_t root, char* hd_path)
{
    return add_ide(root, hd_path, "hda", 1, 0, 0, 0);
}


pet_xml_t
v3_add_hdb(pet_xml_t root, char* hd_path)
{
    return add_ide(root, hd_path, "hdb", 1, 0, 1, 0);
}


/*
pet_xml_t
v3_add_hdc(pet_xml_t root, char* hd_path)
{
    return add_ide(root, hd_path, "hdb", 1, 1, 0, 0);
}
*/

pet_xml_t
v3_add_cd(pet_xml_t root, char* cd_path)
{
    return add_ide(root, cd_path, "cdrom", 0, 1, 0, 1);
}


pet_xml_t
v3_add_vd(pet_xml_t root, char* vd_path)
{
  pet_xml_t vd = NULL;

  /* TODO: Count how many virtio block devices are already present
           Set the ID to be LNX_VIRTIO_BLK-<index> based on that count
  */
  vd = v3_make_device("LNX_VIRTIO_BLK", "blk_virtio");


  /* TODO: Add search function to find the PCI device 
   */
  pet_xml_add_val(vd , "bus" , "pci0");

  v3_add_device(root, vd); 
  
  return vd;
}


pet_xml_t
v3_make_device(char* id, char* class)
{
  
  pet_xml_t device = NULL;
  
  device = pet_xml_new_tree("device");
  
  pet_xml_add_val(device, "id"   , id   );
  pet_xml_add_val(device, "class", class);
  
  return device;
}


pet_xml_t
v3_add_curses(pet_xml_t root)
{

  pet_xml_t    curses       = NULL;
  pet_xml_t    curses_front = NULL;
  pet_xml_t    cga          = NULL;

  curses   = v3_make_device("CURSES_CONSOLE" , "curses" );
  cga      = v3_make_device("CGA_VIDEO"      , "cga"    );

  curses_front = pet_xml_add_subtree(curses, "frontend");

  pet_xml_add_val(curses_front , "tag"        , "cga"    );
  pet_xml_add_val(cga          , "passthrough", "disable");

  v3_add_device( root , cga   );
  v3_add_device( root , curses);
  

  return curses;
}


int
v3_set_mem_size(pet_xml_t root, uint64_t mem_size)
{
  pet_xml_t mem_tree = NULL;
  char*     mem_str  = NULL;

  asprintf(&mem_str, "%lu", mem_size);

  mem_tree = pet_xml_add_subtree(root, "memory");
  pet_xml_add_val(mem_tree, "size", mem_str );

  free(mem_str);
  
  return 0;
}


int
v3_set_num_cpus(pet_xml_t root, uint32_t num_cpus)
{
  pet_xml_t core_tree = NULL;
  char*     cpu_str   = NULL;
  int       i         = 0;

  asprintf(&cpu_str, "%u", num_cpus);

  core_tree = pet_xml_add_subtree(root, "cores");
  pet_xml_add_val(core_tree, "count", cpu_str);

  for(i = 0; i < num_cpus; i++){
    pet_xml_add_val(core_tree, "core", "");
  }

  free(cpu_str);
  
  return 0;
}


int
v3_disable_large_pages(pet_xml_t root)
{
  pet_xml_t iter = NULL;
  
  iter = pet_xml_get_subtree(root, "paging");
  iter = ezxml_child(iter, "large_pages");
  if(iter != NULL){
    ezxml_set_txt(iter, "false");
  }

  return 0;
}


int
v3_disable_nested_pages(pet_xml_t root)
{
  pet_xml_t pages = NULL;
  
  pages = pet_xml_get_subtree(root, "paging");
  
  pet_xml_add_val(pages, "mode", "shadow" );

  return 0;
}
