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


#include "v3_ctrl.h"
#include <ezxml.h>

struct file_info {
    int  size;
    char filename[2048];
    char id[256];
};


static int 
read_file(int             fd, 
	  int             size, 
	  unsigned char * buf) 
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



static char * 
get_val(ezxml_t   cfg,
	char    * tag) 
{
    char   * attrib = (char *)ezxml_attr(cfg, tag);
    ezxml_t  txt    = ezxml_child(cfg, tag);
    char   * val    = NULL;

    if ((txt != NULL) && (attrib != NULL)) {
	ERROR("Invalid Cfg file: Duplicate value for %s (attr=%s, txt=%s)\n", 
	       tag, attrib, ezxml_txt(txt));
	return NULL;
    }

    val = (attrib == NULL) ? ezxml_txt(txt) : attrib;

    /* An non-present value actually == "". So we check if the 1st char is '/0' and return NULL */
    if (!*val) return NULL;

    return val;
}


static struct file_info * 
parse_aux_files(ezxml_t  cfg_input, 
		int    * num_files) 
{
    struct file_info * files = NULL;
    ezxml_t file_tags        = NULL;
    ezxml_t tmp_file_tag     = NULL;
    int i        = 0;
    int file_cnt = 0;

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








static int 
create_vm(char         * vm_name, 
	  void         * img_data,
	  unsigned int   img_size) 
{
    struct v3_guest_img guest_img;

    int v3_fd   = 0;
    int dev_idx = 0;

    memset(&guest_img, 0, sizeof(struct v3_guest_img));

    guest_img.size       = img_size;
    guest_img.guest_data = img_data;
    strncpy(guest_img.name, vm_name, 127);


    v3_fd = open(v3_dev, O_RDONLY);

    if (v3_fd == -1) {
	printf("Error opening V3Vee control device\n");
	return -1;
    }

    dev_idx = ioctl(v3_fd, V3_CREATE_GUEST, &guest_img); 


    if (dev_idx < 0) {
	printf("Error (%d) creating VM\n", dev_idx);
	return -1;
    }

    printf("VM (%s) created at /dev/v3-vm%d\n", vm_name, dev_idx);

    /* Close the file descriptor.  */ 
    close(v3_fd); 

    return 0;
}


int 
v3_load_vm_image(char * vm_name, 
		 char * image_file)
{
    struct stat guest_stats;

    int    guest_fd = 0;
    int    img_size = 0;
    void * img_data = NULL;

    guest_fd = open(image_file, O_RDONLY); 

    if (guest_fd == -1) {
	printf("Error Opening guest image: %s\n", image_file);
	return -1;
    }

    if (fstat(guest_fd, &guest_stats) == -1) {
	printf("ERROR: Could not stat guest image file -- %s\n", image_file);
	return -1;
    }
    
    img_size = guest_stats.st_size;

    // load guest image into user memory
    img_data = malloc(img_size);

    read_file(guest_fd, img_size, img_data);
    
    close(guest_fd);

    printf("Guest image Loaded (size=%u)\n", img_size);
    return create_vm(vm_name, img_data, img_size);
}


int 
v3_create_vm(char  * vm_name, 
	     ezxml_t vm_xml_cfg)
{
    struct file_info * files     = NULL;

    int    num_files      = 0;
    void * guest_img_data = NULL;
    int    guest_img_size = 0;

    int i = 0;


    // parse files
    files = parse_aux_files(vm_xml_cfg, &num_files);
    
    // create image data blob
    {
	unsigned long long   file_offset = 0;
	char               * new_xml_str = ezxml_toxml(vm_xml_cfg);

	int file_data_size = 0;
	int offset         = 0;
	int i              = 0;

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

	*(unsigned int *)(guest_img_data + offset) = strlen(new_xml_str);
	offset += 4;

	memcpy(guest_img_data + offset, new_xml_str, strlen(new_xml_str));
	offset += strlen(new_xml_str);

	memset(guest_img_data + offset, 0, 8);
	offset += 8;
	
	*(unsigned long long *)(guest_img_data + offset) = num_files;
	offset += 8;

	
	// The file offset starts at the end of the file list
	file_offset = offset + (16 * num_files) + 8;

	for (i = 0; i < num_files; i++) {
	    *(unsigned int *)(guest_img_data + offset) = i;
	    offset += 4;
	    *(unsigned int *)(guest_img_data + offset) = files[i].size;
	    offset += 4;
	    *(unsigned long long *)(guest_img_data + offset) = file_offset;
	    offset += 8;

	    file_offset += files[i].size;

	}

	memset(guest_img_data + offset, 0, 8);
	offset += 8;


	for (i = 0; i < num_files; i++) {
	    int fd = open(files[i].filename, O_RDONLY);

	    if (fd == -1) {
		printf("Error: Could not open aux file (%s)\n", files[i].filename);
		free(new_xml_str);
		free(files);
		return -1;
	    }

	    read_file(fd, files[i].size, (unsigned char *)(guest_img_data + offset));

	    close(fd);

	    offset += files[i].size;

	}

	free(files);	
	free(new_xml_str);
    }

    printf("Guest Image Created (size=%u)\n", guest_img_size);
    create_vm(vm_name, guest_img_data, guest_img_size);


    free(guest_img_data);

    return 0;
}





#if 0
int main(int argc, char ** argv) {
    char * filename = NULL;
    char * name     = NULL;

    int build_flag  = 0;
    int c           = 0;

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
    name     = argv[optind + 1];


    if (build_flag == 1) {
	int i = 0;

	printf("Building VM Image (cfg=%s) (name=%s)\n", filename, name);

	return build_image(name, filename);


    } else {
	printf("Loading VM Image (img=%s) (name=%s)\n", filename, name);
	return load_image(name, filename);
    }

    return 0; 
} 




#endif
