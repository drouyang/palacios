//xml config
//Charles Smith <cas275@pitt.edu>



#include "pet_xml.h"
#include "v3_config.h"
#include "ezxml.h"
#include <string.h>


//methods that should only need to be used in here
//the rest can be found in "config.h"
pet_xml_t  v3_set_mem_amount(pet_xml_t root, int  mem_amount );
pet_xml_t     v3_set_num_cpu(pet_xml_t root, int  num_cpu    );
void               v3_add_hd(pet_xml_t root, char* hd_path, char* id, char* drive_num);


pet_xml_t 
v3_create_config(int  mem_amount, int  num_cpu)
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
  ezxml_set_attr(root, "class", "PC");


  v3_set_mem_amount(root,  mem_amount);


  /* sets the paging to the defaults */
  {
    pet_xml_t page = NULL;
    
    page = pet_xml_new_tree("paging");
    
    ezxml_set_attr(page, "mode", "nested");
    pet_xml_add_val(page, "large_pages", "true");
    
    ezxml_insert(page, root, 0); 
  }


  pet_xml_add_val(root, "schedule_hz", "100");


  v3_set_num_cpu(root,  num_cpu  );


  pet_xml_add_subtree(root, "devices");


  apic        = v3_make_device("apic"       , "LAPIC"     );
  keyboard    = v3_make_device("keyboard"   , "KEYBOARD"  );
  pit         = v3_make_device("PIT"        , "8254_PIT"  );
  ioapic      = v3_make_device("ioapic"     , "IOAPIC"    );
  pci         = v3_make_device("pci0"       , "PCI"       );
  northbridge = v3_make_device("northbridge", "i440FX"    );
  southbridge = v3_make_device("southbridge", "PIIX3"     );
  nvram       = v3_make_device("nvram"      , "NVRAM"     );

  
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
    
    ide = v3_make_device("ide", "IDE");
    
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


void
v3_add_hd(pet_xml_t root, char* hd_path, char* id, char* drive_num)
{
  pet_xml_t hd          = NULL;
  pet_xml_t hd_frontend = NULL;


  hd = pet_xml_new_tree("device");

  hd_frontend = pet_xml_add_subtree(hd, "frontend");
  
  ezxml_set_attr(hd         , "id"      ,  id       );
  ezxml_set_attr(hd         , "class"   , "FILEDISK");
  ezxml_set_attr(hd         , "writable", "1"       );
  ezxml_set_attr(hd_frontend, "tag"     , "ide"     );

  pet_xml_add_val(hd         , "path"     , hd_path    );
  pet_xml_add_val(hd_frontend, "model"    , "V3Vee HDD");

  if(atoi(drive_num)<3){
    pet_xml_add_val(hd_frontend, "bus_num"  , "0"        );
    pet_xml_add_val(hd_frontend, "drive_num", drive_num  );
  }
  else{
    pet_xml_add_val(hd_frontend, "bus_num"  , "1" );
    pet_xml_add_val(hd_frontend, "drive_num", "1" );
  }    

  pet_xml_add_val(hd_frontend, "type"     , "HD" );

  v3_add_device(root, hd);

}


pet_xml_t
v3_add_hda(pet_xml_t root, char* hd_path)
{
  v3_add_hd(root, hd_path, "hd0", "0");
  return root;
}


pet_xml_t
v3_add_hdb(pet_xml_t root, char* hd_path)
{
  v3_add_hd(root, hd_path, "hd1", "1");
  return root;
}


pet_xml_t
v3_add_hdc(pet_xml_t root, char* hd_path)
{
  v3_add_hd(root, hd_path, "hd2", "2");
  return root;
}


pet_xml_t
v3_add_cd(pet_xml_t root, char* cd_path)
{
  pet_xml_t cd          = NULL;
  pet_xml_t cd_frontend = NULL;

  cd = pet_xml_new_tree("device");

  cd_frontend = pet_xml_add_subtree(cd, "frontend");
  
  ezxml_set_attr(cd         , "id"      , "cd"      );
  ezxml_set_attr(cd         , "class"   , "FILEDISK");
  ezxml_set_attr(cd         , "writable", "0"       );
  ezxml_set_attr(cd_frontend, "tag"     , "ide"     );

  pet_xml_add_val(cd         , "path"     , cd_path      );
  pet_xml_add_val(cd_frontend, "model"    , "V3Vee CDROM");
  pet_xml_add_val(cd_frontend, "bus_num"  , "1"          );
  pet_xml_add_val(cd_frontend, "drive_num", "0"          );
  pet_xml_add_val(cd_frontend, "type"     , "CDROM"      );

  v3_add_device(root, cd);
  
  return root;
}


pet_xml_t
v3_add_vd(pet_xml_t root, char* vd_path)
{
  pet_xml_t vd = NULL;

  vd = v3_make_device("blk_virtio", "LNX_VIRTIO_BLK");
  
  pet_xml_add_val(vd , "bus" , "pci0");

  v3_add_device(root, vd); 
  
  return root;
}


pet_xml_t
v3_make_device(char* id, char* class)
{
  
  pet_xml_t device = NULL;
  
  device = pet_xml_new_tree("device");
  
  ezxml_set_attr(device, "id"   , id   );
  ezxml_set_attr(device, "class", class);
  
  return device;
}


pet_xml_t
v3_add_curses(pet_xml_t root)
{

  pet_xml_t    curses       = NULL;
  pet_xml_t    curses_front = NULL;
  pet_xml_t    cga          = NULL;

  curses   = v3_make_device("curses" , "CURSES_CONSOLE");
  cga      = v3_make_device("cga"    , "CGA_VIDEO"     );

  curses_front = pet_xml_add_subtree(curses, "frontend");

  ezxml_set_attr(curses_front , "tag"        , "cga"    );
  ezxml_set_attr(cga          , "passthrough", "disable");

  v3_add_device( root , cga   );
  v3_add_device( root , curses);
  

  return root;
}

//TODO
//seperate into disable large pages, disable nested paging
pet_xml_t
set_paging(pet_xml_t root, char* mode, char* large)
{
  pet_xml_t page = NULL;
  
  page = pet_xml_new_tree("paging");

  ezxml_set_attr(page, "mode", mode);
  pet_xml_add_val(page, "large_pages", large);

  ezxml_insert(page, root, 0);
  
  return root;
}


pet_xml_t
v3_set_mem_amount(pet_xml_t root, int mem_amount)
{
  pet_xml_t memory = NULL;
  char*      mem   = malloc(32);

  sprintf(mem, "%d", mem_amount);
  memory = pet_xml_add_subtree(root, "memory");
  ezxml_set_attr(memory, "size", mem );

  return root;
}


pet_xml_t
v3_set_num_cpu(pet_xml_t root, int num_cpu)
{
  pet_xml_t cores    = NULL;
  int       i        = 0;
  char*     cpu      = malloc(32);

  sprintf(cpu, "%d", num_cpu);

  cores = pet_xml_add_subtree(root, "cores");
  ezxml_set_attr(cores, "count", cpu);

  for(i = 0; i < num_cpu; i++){
    pet_xml_add_val(cores, "core", "");
  }

  return root;
}


void
v3_disable_large_pages(pet_xml_t root)
{
  pet_xml_t iter = NULL;
  
  iter = pet_xml_get_subtree(root, "paging");
  iter = ezxml_child(iter, "large_pages");
  if(iter != NULL){
    ezxml_set_txt(iter, "false");
  }
  
}


void
v3_disable_nested_pages(pet_xml_t root)
{
  pet_xml_t pages = NULL;
  
  pages = pet_xml_get_subtree(root, "paging");
  
  ezxml_set_attr(pages, "mode", "shadow" );

}
