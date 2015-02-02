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



#include "v3_types.h"
#include "v3_ioctl.h"
#include <ezxml.h>

struct file_info {
    u32 size;
    char     filename[2048];
    char     id[256];
};


static int 
read_file(int   fd, 
	  int   size, 
	  u8  * buf) 
{
    int left_to_read = size;
    int have_read    = 0;

    while (left_to_read != 0) {
	int bytes_read = read(fd, buf + have_read, left_to_read);

	if (bytes_read <= 0) {
	    break;
	}

	have_read    += bytes_read;
	left_to_read -= bytes_read;
    }

    if (left_to_read != 0) {
	printf("Error could not finish reading file\n");
	return -1;
    }
    
    return 0;
}


static int 
write_file(int   fd, 
	   int   size,
	   u8  * buf)
{
    int left_to_write = size;
    int have_written  = 0;

    while (left_to_write != 0) {
	int bytes_written = write(fd, buf + have_written, left_to_write);

	if (bytes_written <= 0) {
	    break;
	}

	have_written  += bytes_written;
	left_to_write -= bytes_written;
    }

    if (left_to_write != 0) {
	printf("Error Could not finish writing file\n");
	return -1;
    }

    return 0;
}



static char * 
get_val(ezxml_t   cfg,
	char    * tag) 
{
    char   * attrib = (char *)ezxml_attr(cfg, tag);
    ezxml_t  txt    = ezxml_child(cfg, tag);
    char   * val    = NULL;

    if ((txt != NULL) && (attrib != NULL)) {
	printf("Error: Invalid Cfg file: Duplicate value for %s (attr=%s, txt=%s)\n", 
	       tag, attrib, ezxml_txt(txt));
	return NULL;
    }

    val = (attrib == NULL) ? ezxml_txt(txt) : attrib;

    /* An non-present value actually == "". So we check if the 1st char is '/0' and return NULL */
    if (!*val) return NULL;

    return val;
}


static struct file_info * 
parse_aux_files(ezxml_t   cfg_input, 
	 	u32     * num_files) 
{
    struct file_info * files = NULL;
    ezxml_t  file_tags       = NULL;
    ezxml_t  tmp_file_tag    = NULL;

    u32 file_cnt = 0;
    int i        = 0;

    // files are transformed into blobs that are slapped to the end of the file
    
    /* 
     * First we count the number of files 
     */
    file_tags    = ezxml_child(cfg_input, "files");
    tmp_file_tag = ezxml_child(file_tags, "file");

    while (tmp_file_tag) {
	file_cnt++;
	tmp_file_tag = ezxml_next(tmp_file_tag);
    }

    files   = malloc(sizeof(struct file_info) * file_cnt);
    memset(files, 0, sizeof(struct file_info) * file_cnt);

    
    file_tags    = ezxml_child(cfg_input, "files");
    tmp_file_tag = ezxml_child(file_tags, "file");

    for (i = 0; i < file_cnt; i++) {
	struct stat file_stats;

	char   index_buf[256] = {[0 ... 255] = 0};
	char * filename       = get_val(tmp_file_tag, "filename");
	char * id             = get_val(tmp_file_tag, "id");


	if (stat(filename, &file_stats) != 0) {
	    perror(filename);

	    i--;
	    file_cnt--;
	    continue;
	}

	files[i].size = (unsigned int)file_stats.st_size;
	strncpy(files[i].id,       id,       256);
	strncpy(files[i].filename, filename, 2048);

	snprintf(index_buf, 256, "%llu", i);
	ezxml_set_attr_d(tmp_file_tag, "index", index_buf);


	tmp_file_tag = ezxml_next(tmp_file_tag);
    }

    *num_files = file_cnt;


    return files;
}







int 
v3_create_vm(char * vm_name, 
	     u8   * img_data,
	     u32    img_size) 
{
    struct v3_guest_img guest_img;
    int vm_id = 0;

    memset(&guest_img, 0, sizeof(struct v3_guest_img));

    guest_img.size       = img_size;
    guest_img.guest_data = (uintptr_t)img_data;
    strncpy(guest_img.name, vm_name, 127);

    vm_id = pet_ioctl_path(V3_DEV_FILENAME, V3_CREATE_GUEST, &guest_img);

    if (vm_id < 0) {
	printf("Error (%d) creating VM\n", vm_id);
	return -1;
    }

    printf("VM (%s) created at " V3_VM_FILENAME "%s\n", vm_name, vm_id);

    return vm_id;
}


int
v3_load_vm_image(char  * file_name,
		 u8   ** img_data,
		 u32   * img_size)
{
    struct stat guest_stats;

    int   guest_fd = 0;
    u8  * data = NULL;
    u32   size = 0;
    int   ret  = 0;

    guest_fd = open(file_name, O_RDONLY); 

    if (guest_fd == -1) {
	printf("Error Opening guest image: %s\n", file_name);
	return -1;
    }

    if (fstat(guest_fd, &guest_stats) == -1) {
	printf("ERROR: Could not stat guest image file -- %s\n", file_name);
	return -1;
    }
    

    // load guest image into user memory
    data = malloc(size);

    ret = read_file(guest_fd, size, data);
    
    close(guest_fd);

    if (ret != 0) {
	printf("Error Could not load VM image (%s)\n", file_name);
	return -1;
    }

    *img_size = size;
    *img_data = data;


    return 0;
}



int 
v3_save_vm_image(char * file_name, 
		 u8   * img_data,
		 u32    img_size) 
{    
    int guest_fd = 0;
    int ret      = 0;

    guest_fd = open(file_name, O_RDWR | O_CREAT | O_TRUNC);

    if (guest_fd == -1) {
	printf("Error opening guest image for writing: %s\n", file_name);
	return -1;
    }

    ret = write_file(guest_fd, img_size, img_data);

    close(guest_fd);

    if (ret != 0) {
	printf("Error: Could not save VM image (%s)\n", file_name);
	return -1;
    }

    return 0;
}


ezxml_t 
v3_load_vm_cfg(char * file_name) 
{

    ezxml_t xml_input = ezxml_parse_file(file_name);
    
    if (xml_input == NULL) {
	printf("Error: Could not open XML input file (%s)\n", file_name);
	return NULL;
    } else if (strcmp("", ezxml_error(xml_input)) != 0) {
	printf("%s\n", ezxml_error(xml_input));
	return NULL;
    }

    return xml_input;
}

int
v3_save_vm_cfg(char    * file_name,
	       ezxml_t   vm_xml_cfg)
{
    char * xml_str = ezxml_toxml(vm_xml_cfg);
    int    xml_fd  = 0;
    int    ret     = 0;

    xml_fd = open(file_name, O_RDWR | O_CREAT | O_TRUNC);

    if (xml_fd == -1) {
	printf("Error: Could not open cfg file (%s)\n", file_name);
	return -1;
    }

    ret = write_file(xml_fd, strlen(xml_str), xml_str);

    close(xml_fd);
    
    if (ret != 0) {
	printf("Error: Could not save VM XML cfg (%s)\n", file_name);
	return -1;
    }
    
    return 0;
}

u8 * 
v3_build_vm_image(ezxml_t   vm_xml_cfg, 
		  u32     * img_size)
{
    struct file_info * files = NULL;

    int    num_files         = 0;
    void * guest_img_data    = NULL;
    int    guest_img_size    = 0;

    int i = 0;


    // parse files
    files = parse_aux_files(vm_xml_cfg, &num_files);
    
    // create image data blob
    {
	u64    file_offset    = 0;
	char * new_xml_str    = ezxml_toxml(vm_xml_cfg);
	int    file_data_size = 0;
	int    offset         = 0;
	int    i              = 0;

	/* Image size is: 
	   8 byte header + 
	   4 byte xml length + 
	   xml strlen + 
	   8 bytes of zeros + 
	   8 bytes (number of files) + 
	   num_files * 16 byte file header + 
	   8 bytes of zeroes + 
	   file data
	*/
	for (i = 0; i < num_files; i++) {
	    file_data_size += files[i].size;
	}

	guest_img_size = 8 + 4 + strlen(new_xml_str) + 8 + 8 + 
	    (num_files * 16) + 8 + file_data_size;
	    

	guest_img_data = malloc(guest_img_size);
	memset(guest_img_data, 0, guest_img_size);

	memcpy(guest_img_data, "v3vee\0\0\0", 8);
	offset += 8;

	*(u32 *)(guest_img_data + offset) = strlen(new_xml_str);
	offset += 4;

	memcpy(guest_img_data + offset, new_xml_str, strlen(new_xml_str));
	offset += strlen(new_xml_str);

	memset(guest_img_data + offset, 0, 8);
	offset += 8;
	
	*(u64 *)(guest_img_data + offset) = num_files;
	offset += 8;

	
	// The file offset starts at the end of the file list
	file_offset = offset + (16 * num_files) + 8;

	for (i = 0; i < num_files; i++) {
	    *(u32 *)(guest_img_data + offset) = i;
	    offset += 4;
	    *(u32 *)(guest_img_data + offset) = files[i].size;
	    offset += 4;
	    *(u64 *)(guest_img_data + offset) = file_offset;
	    offset += 8;

	    file_offset += files[i].size;

	}

	memset(guest_img_data + offset, 0, 8);
	offset += 8;


	for (i = 0; i < num_files; i++) {
	    int fd = open(files[i].filename, O_RDONLY);

	    if (fd == -1) {
		printf("Error: Could not open aux file (%s)\n", files[i].filename);
		free(guest_img_data);
		free(new_xml_str);
		free(files);
		return NULL;
	    }

	    read_file(fd, files[i].size, (u8 *)(guest_img_data + offset));

	    close(fd);

	    offset += files[i].size;

	}

	free(files);	
	free(new_xml_str);
    }


    *img_size = guest_img_size;

    return guest_img_data;
}



