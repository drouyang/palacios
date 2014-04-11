#include "kitten-exts.h"
#include <linux/rbtree.h>

/* 
 * This is a place holder to ensure that the _lwk_exts section gets created by gcc
 */

static struct {} null_ext  __attribute__((__used__))                    \
    __attribute__((unused, __section__ ("_v3_lwk_exts"),			\
		   aligned(sizeof(void *))));



/* 
 * VM Controls
 */

struct vm_ctrl {
    unsigned int cmd;

    int (*handler)(struct v3_guest * guest, 
		   unsigned int cmd, unsigned long arg, 
		   void * priv_data);

    void * priv_data;

    struct rb_node tree_node;
};



static inline struct vm_ctrl * __insert_ctrl(struct v3_guest * vm, 
					     struct vm_ctrl * ctrl) {
    struct rb_node ** p = &(vm->vm_ctrls.rb_node);
    struct rb_node * parent = NULL;
    struct vm_ctrl * tmp_ctrl = NULL;

    while (*p) {
	parent = *p;
	tmp_ctrl = rb_entry(parent, struct vm_ctrl, tree_node);

	if (ctrl->cmd < tmp_ctrl->cmd) {
	    p = &(*p)->rb_left;
	} else if (ctrl->cmd > tmp_ctrl->cmd) {
	    p = &(*p)->rb_right;
	} else {
	    return tmp_ctrl;
	}
    }

    rb_link_node(&(ctrl->tree_node), parent, p);

    return NULL;
}



int add_guest_ctrl(struct v3_guest * guest, unsigned int cmd, 
		   int (*handler)(struct v3_guest * guest, 
				  unsigned int cmd, unsigned long arg, 
				  void * priv_data),
		   void * priv_data) {
    struct vm_ctrl * ctrl = kmem_alloc(sizeof(struct vm_ctrl));

    if (ctrl == NULL) {
	printk("Error: Could not allocate vm ctrl %d\n", cmd);
	return -1;
    }

    ctrl->cmd = cmd;
    ctrl->handler = handler;
    ctrl->priv_data = priv_data;

    if (__insert_ctrl(guest, ctrl) != NULL) {
	printk("Could not insert guest ctrl %d\n", cmd);
	kmem_free(ctrl);
	return -1;
    }
    
    rb_insert_color(&(ctrl->tree_node), &(guest->vm_ctrls));

    return 0;
}




static struct vm_ctrl * get_ctrl(struct v3_guest * guest, unsigned int cmd) {
    struct rb_node * n = guest->vm_ctrls.rb_node;
    struct vm_ctrl * ctrl = NULL;

    while (n) {
	ctrl = rb_entry(n, struct vm_ctrl, tree_node);

	if (cmd < ctrl->cmd) {
	    n = n->rb_left;
	} else if (cmd > ctrl->cmd) {
	    n = n->rb_right;
	} else {
	    return ctrl;
	}
    }
    
    return NULL;
}

int call_guest_ctrl(struct v3_guest * guest, unsigned int cmd, unsigned long arg) {
    struct vm_ctrl * ctrl = get_ctrl(guest, cmd);

    if (ctrl == NULL) {
	printk("Error Could not find guest control for cmd %d\n", cmd);
	return -EINVAL;
    }
	
    return ctrl->handler(guest, cmd, arg, ctrl->priv_data);;	
}

int remove_guest_ctrl(struct v3_guest * guest, unsigned int cmd) {
    struct vm_ctrl * ctrl = get_ctrl(guest, cmd);

    if (ctrl == NULL) {
	printk("Could not find control (%d) to remove\n", cmd);
	return -1;
    }

    rb_erase(&(ctrl->tree_node), &(guest->vm_ctrls));

    kmem_free(ctrl);

    return 0;
}

void free_guest_ctrls(struct v3_guest * guest) {
    struct rb_node * node = rb_first(&(guest->vm_ctrls));
    struct vm_ctrl * ctrl = NULL;

    while (node) {
	ctrl = rb_entry(node, struct vm_ctrl, tree_node);
	node = rb_next(node);
	
	printk("Cleaning up guest ctrl that was not removed explicitly (%d)\n", ctrl->cmd);

	kmem_free(ctrl);
    }
}




/*                 */
/* Global controls */
/*                 */

struct rb_root global_ctrls;

static inline struct global_ctrl * __insert_global_ctrl(struct global_ctrl * ctrl) {
    struct rb_node ** p = &(global_ctrls.rb_node);
    struct rb_node * parent = NULL;
    struct global_ctrl * tmp_ctrl = NULL;

    while (*p) {
        parent = *p;
        tmp_ctrl = rb_entry(parent, struct global_ctrl, tree_node);

        if (ctrl->cmd < tmp_ctrl->cmd) {
            p = &(*p)->rb_left;
        } else if (ctrl->cmd > tmp_ctrl->cmd) {
            p = &(*p)->rb_right;
        } else {
            return tmp_ctrl;
        }
    }

    rb_link_node(&(ctrl->tree_node), parent, p);

    return NULL;
}



int add_global_ctrl(unsigned int cmd, 
                   int (*handler)(unsigned int cmd, unsigned long arg)) {
    struct global_ctrl * ctrl = kmem_alloc(sizeof(struct global_ctrl));

    if (ctrl == NULL) {
        printk("Error: Could not allocate global ctrl %d\n", cmd);
        return -1;
    }

    ctrl->cmd = cmd;
    ctrl->handler = handler;

    if (__insert_global_ctrl(ctrl) != NULL) {
        printk("Could not insert guest ctrl %d\n", cmd);
        kmem_free(ctrl);
        return -1;
    }
    
    rb_insert_color(&(ctrl->tree_node), &(global_ctrls));

    return 0;
}


struct global_ctrl * get_global_ctrl(unsigned int cmd) {
    struct rb_node * n = global_ctrls.rb_node;
    struct global_ctrl * ctrl = NULL;

    while (n) {
        ctrl = rb_entry(n, struct global_ctrl, tree_node);

        if (cmd < ctrl->cmd) {
            n = n->rb_left;
        } else if (cmd > ctrl->cmd) {
            n = n->rb_right;
        } else {
            return ctrl;
        }
    }

    return NULL;
}





/*               */
/* VM Extensions */
/*               */

struct vm_ext {
    struct kitten_ext * impl;
    void * vm_data;
    struct list_head node;
};


void * get_vm_ext_data(struct v3_guest * guest, char * ext_name) {
    struct vm_ext * ext = NULL;

    list_for_each_entry(ext, &(guest->exts), node) {
	if (strncmp(ext->impl->name, ext_name, strlen(ext->impl->name)) == 0) {
	    return ext->vm_data;
	}
    }

    return NULL;
}


int init_vm_extensions(struct v3_guest * guest) {
    extern struct kitten_ext * __start__v3_lwk_exts[];
    extern struct kitten_ext * __stop__v3_lwk_exts[];
    struct kitten_ext * ext_impl = __start__v3_lwk_exts[0];
    int i = 0;

    printk("Initializing VM extensions\n");

    while (ext_impl != __stop__v3_lwk_exts[0]) {
	struct vm_ext * ext = NULL;

	if (ext_impl->guest_init == NULL) {
	    // We can have global extensions without per guest state
	    ext_impl = __start__v3_lwk_exts[++i];
	    continue;
	}
	
	printk(KERN_INFO "Registering Kitten VM Extension (%s)\n", ext_impl->name);

	ext = kmem_alloc(sizeof(struct vm_ext));
	
	if (!ext) {
	    printk(KERN_WARNING "Error allocating VM extension (%s)\n", ext_impl->name);
	    return -1;
	}

	ext->impl = ext_impl;

	printk("Calling guest init\n");

	ext_impl->guest_init(guest, &(ext->vm_data));

	list_add(&(ext->node), &(guest->exts));

	ext_impl = __start__v3_lwk_exts[++i];
    }
    
    return 0;
}



int deinit_vm_extensions(struct v3_guest * guest) {
    struct vm_ext * ext = NULL;
    struct vm_ext * tmp = NULL;

    list_for_each_entry_safe(ext, tmp, &(guest->exts), node) {
	if (ext->impl->guest_deinit) {
	    ext->impl->guest_deinit(guest, ext->vm_data);
	} else {
	    printk(KERN_WARNING "WARNING: Extension %s, does not have a guest deinit function\n", ext->impl->name);
	}

	list_del(&(ext->node));
	kmem_free(ext);
    }

    return 0;
}


int init_lwk_extensions( void ) {
    extern struct kitten_ext * __start__v3_lwk_exts[];
    extern struct kitten_ext * __stop__v3_lwk_exts[];
    struct kitten_ext * tmp_ext = __start__v3_lwk_exts[0];
    int i = 0;

    printk("Initializing LWK extensions\n");

    while (tmp_ext != __stop__v3_lwk_exts[0]) {

	printk(KERN_DEBUG "tmp_ext=%p\n", tmp_ext);

	if (tmp_ext->init != NULL) {
	    printk(KERN_INFO "Registering Kitten Extension (%s)\n", tmp_ext->name);
	    tmp_ext->init();
	}

	tmp_ext = __start__v3_lwk_exts[++i];
    }
    
    return 0;
}


int deinit_lwk_extensions( void ) {
    extern struct kitten_ext * __start__v3_lwk_exts[];
    extern struct kitten_ext * __stop__v3_lwk_exts[];
    struct kitten_ext * tmp_ext = __start__v3_lwk_exts[0];
    int i = 0;

    while (tmp_ext != __stop__v3_lwk_exts[0]) {
	printk(KERN_INFO "Cleaning up Kitten Extension (%s)\n", tmp_ext->name);

	if (tmp_ext->deinit != NULL) {
	    tmp_ext->deinit();
	} else {
	    printk(KERN_WARNING "WARNING: Extension %s does not have a global deinit function\n", tmp_ext->name);
	}

	tmp_ext = __start__v3_lwk_exts[++i];
    }
    
    return 0;
}

