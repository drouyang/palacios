#include "palacios.h"
#include <lwk/rbtree.h>




struct kitten_ext {
    char * name;
    int (*init)( void );
    int (*deinit)( void );
    int (*guest_init)(struct v3_guest * guest, void ** priv_data);
    int (*guest_deinit)(struct v3_guest * guest, void * priv_data);
};



int init_lwk_extensions( void );
int deinit_lwk_extensions( void );

int init_vm_extensions(struct v3_guest * guest);
int deinit_vm_extensions(struct v3_guest * guest);

void * get_vm_ext_data(struct v3_guest * guest, char * ext_name);



struct global_ctrl {
    unsigned int cmd;

    int (*handler)(unsigned int cmd, unsigned long arg);

    struct rb_node tree_node;
};




int add_guest_ctrl(struct v3_guest * guest, unsigned int cmd, 
		   int (*handler)(struct v3_guest * guest, 
				  unsigned int cmd, unsigned long arg, 
				  void * priv_data),
		   void * priv_data);
int  call_guest_ctrl(struct v3_guest * guest, unsigned int cmd, unsigned long arg);
int remove_guest_ctrl(struct v3_guest * guest, unsigned int cmd);

void free_guest_ctrls(struct v3_guest * guest);

int add_global_ctrl(unsigned int cmd, 
		    int (*handler)(unsigned int cmd, unsigned long arg));

struct global_ctrl * get_global_ctrl(unsigned int cmd);



#define register_extension(ext)					\
    static struct kitten_ext * _lwk_ext				\
    __attribute__((used))					\
	__attribute__((unused, __section__("_v3_lwk_exts"),		\
		       aligned(sizeof(void *))))		\
	= ext;
