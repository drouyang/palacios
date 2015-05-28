//v3_start
//Charles Smith <cas275@pitt.edu>

#include "config.h"
#include "v3vee.h"
#include "pet_xml.h"
#include "ezxml.h"

#include <getopt.h>

#define DEFAULT_MEM  "256"
#define DEFAULT_CPU  "1"
#define DEFAULT_NAME "v3_VM"

static int curses_flag = 0;
static int disable_lp  = 0;  //large pages
static int disable_np  = 0; //nested pages

void usage()
{
  printf("usage\n");
  printf("./config_main [--options]\n");
  printf("options:\n");
  printf("--mem or -m <value>\t\t\tsets the amount of memory in MB\n");
  printf("--cpu or -c <value>\t\t\tsets the number of CPUs\n");
  printf("--hd[a/b] <path>\t\t\tsets the path for hda\n");
  printf("--cd <path>\t\t\t\tsets the path for cd\n");
  printf("--vd <path>\t\t\t\tsets the path for the VD\n");
  printf("--curses\t\t\t\tenables the curses console\n");
  printf("--help or -h\t\t\t\tdisplays this help\n");
  printf("--disablelargep\t\t\t\tdisables large pages\n");
  printf("--disablenestedp\t\t\tdisables nested paging\n");
}


int main(int argc, char** argv)
{
  char*     mem            = DEFAULT_MEM;
  char*     cpu            = DEFAULT_CPU;
  char*     name           = DEFAULT_NAME;
  char*     hda_path       = NULL;
  char*     hdb_path       = NULL;
  char*     cd_path        = NULL;
  char*     vd_path        = NULL;
  pet_xml_t xml            = NULL;
  int       c              = 0;
  int       option_index   = 0;

  //parse inputs
  while(1)
    {
      static struct option long_options[]=
	{
	  {"curses"        , no_argument      , &curses_flag  ,  1 },
	  {"mem"           , required_argument, 0             , 'm'},
	  {"cpu"           , required_argument, 0             , 'c'},
	  {"hda"           , required_argument, 0             ,  4 },
	  {"cd"            , required_argument, 0             ,  5 },
	  {"vd"            , required_argument, 0             ,  6 },
	  {"help"          , no_argument      , 0             , 'h'},
	  {"disablelargep" , no_argument      , &disable_lp   ,  1 },
	  {"disablenestedp", no_argument      , &disable_np   ,  1 },
	  {"hdb"           , required_argument, 0             ,  10},
	  {"name"          , required_argument, 0             ,  11},
	  {0,0,0,0}
	};
      
      c = getopt_long (argc, argv, "m:c:h",long_options, &option_index);
      
      if(c==-1){
	break;
      }
      
      switch(c)
	{
	case 0:
	  break;
	case 'm':
	  mem = optarg;
	  if(atoi(mem)<=0){
	    printf("invalid amount of memory: %s\n",mem);
	    return -1;
	  }
	  break;
	case 'c':
	  cpu = optarg;
	  if(atoi(cpu)<=0){
	    printf("invalid number of CPUs: %s\n",cpu);
	    return -1;
	  }
	  break;
	case 4:
	  hda_path = optarg;
	  break;
	case 5:
	  cd_path = optarg;
	  break;
	case 6:
	  vd_path = optarg;
	  break;
	case 'h':
	  usage();
	  return -1;
	case 10:
	  hdb_path = optarg;
	  break;
	case 11:
	  name = optarg;
	  break;
	default:
	  usage();
	  return -1;
	}
    }
  

  //let's print out the inputs, for debuging purposes
  printf("mem: %d\n", atoi(mem));
  printf("cpu: %d\n", atoi(cpu));

  //making the xml, as the user specified
  xml = v3_create_default_config(atoi(mem), atoi(cpu));
  if(curses_flag){
    v3_add_curses(xml);
    printf("added curses console\n");
  }
  if(hda_path){
    v3_add_hda(xml,hda_path);
    printf("added hda with path: %s\n",hda_path);
  }
  if(hdb_path){
    v3_add_hdb(xml,hdb_path);
    printf("added hdb with path: %s\n",hdb_path);
  }
  if(cd_path){
    v3_add_cd(xml, cd_path);
    printf("added cd with path:  %s\n", cd_path);
  }
  if(vd_path){
    v3_add_vd(xml,vd_path);
    printf("added vd with path: %s\n", vd_path);
  }
  if(disable_lp){
    v3_disable_large_pages(xml);
    printf("disabled large pages\n");
  }
  if(disable_np){
    v3_disable_nested_pages(xml);
    printf("disabled nested_pages\n");
  }


  /* save the xml for debuging purposes */
  {
    FILE* out    = NULL;
    char* result = NULL;
    result = pet_xml_get_str(xml);
    
       
    //saving the xml to a file
    out = fopen("./v3_start.xml", "w");
    fprintf(out,"%s",result);
    fclose(out);
    
    printf("saved xml to ./v3_start.xml\n");
    
    free(result); 
  }
  

  /*create the VM */
  {
    u8* img_data = NULL;
    u32 img_size = NULL;
    int vm_id    = NULL;
    int launch   = 0;
 
   
    printf("Building VM image\n");
    img_data = v3_build_vm_image(xml, &img_size);
    if(!img_data){
      printf("error building the image\n");
      return -1;
    }


    printf("Creating VM\n");
    vm_id = v3_create_vm(name, img_data, img_size);
    if(vm_id<0){
      printf("error creating the vm (vm id <0)\n");
      return -1;
    }
    printf("vm id: %d\n",vm_id);


    printf("launching VM\n");
    launch = v3_launch_vm(vm_id);
    if(launch!=0){
      printf("error launching VM\n");
      return -1;
    }
  }
    

  return 0;
}
