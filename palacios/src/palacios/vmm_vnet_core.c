/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2010, Lei Xia <lxia@northwestern.edu> 
 * Copyright (c) 2009, Yuan Tang <ytang@northwestern.edu>  
 * Copyright (c) 2009, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Lei Xia <lxia@northwestern.edu>
 *	   Yuan Tang <ytang@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */
 
#include <palacios/vmm_vnet.h>
#include <palacios/vm_guest_mem.h>
#include <palacios/vmm_lock.h>
#include <palacios/vmm_queue.h>
#include <palacios/vmm_sprintf.h>
#include <palacios/vmm_ethernet.h>

#ifndef CONFIG_DEBUG_VNET
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

struct eth_hdr {
    uint8_t dst_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t type; /* indicates layer 3 protocol type */
} __attribute__((packed));


struct vnet_dev {
    int dev_id;
    uint8_t mac_addr[ETH_ALEN];
    struct v3_vm_info * vm;
    struct v3_vnet_dev_ops dev_ops;
    void * private_data;

    int active;
    vnet_poll_type_t mode;  //vmm_drivern or guest_drivern
    
    struct list_head node;
} __attribute__((packed));


struct vnet_brg_dev {
    struct v3_vm_info * vm;
    struct v3_vnet_bridge_ops brg_ops;

    uint8_t type;
    vnet_poll_type_t mode;
    int active;
    void * private_data;
} __attribute__((packed));



struct vnet_route_info {
    struct v3_vnet_route route_def;

    struct vnet_dev * dst_dev;
    struct vnet_dev * src_dev;

    struct list_head node;
    struct list_head match_node; // used for route matching
};


struct route_list {
    uint8_t hash_buf[VNET_HASH_SIZE];

    uint32_t num_routes;
    struct vnet_route_info * routes[0];
} __attribute__((packed));


static struct {
    struct list_head routes;
    struct list_head devs;
    
    int num_routes;
    int num_devs;

    struct vnet_brg_dev *bridge;

    v3_lock_t lock;
    struct vnet_stat stats;

    struct hashtable * route_cache;
} vnet_state;



#ifdef CONFIG_DEBUG_VNET
static inline void mac_to_string(uint8_t * mac, char * buf) {
    snprintf(buf, 100, "%2x:%2x:%2x:%2x:%2x:%2x", 
	     mac[0], mac[1], mac[2],
	     mac[3], mac[4], mac[5]);
}

static void print_route(struct v3_vnet_route * route){
    char str[50];

    mac_to_string(route->src_mac, str);
    PrintDebug("Src Mac (%s),  src_qual (%d)\n", 
	       str, route->src_mac_qual);
    mac_to_string(route->dst_mac, str);
    PrintDebug("Dst Mac (%s),  dst_qual (%d)\n", 
	       str, route->dst_mac_qual);
    PrintDebug("Src dev id (%d), src type (%d)", 
	       route->src_id, 
	       route->src_type);
    PrintDebug("Dst dev id (%d), dst type (%d)\n", 
	       route->dst_id, 
	       route->dst_type);
}

static void dump_routes(){
    struct vnet_route_info *route;

    int i = 0;
    PrintDebug("\n========Dump routes starts ============\n");
    list_for_each_entry(route, &(vnet_state.routes), node) {
    	PrintDebug("\nroute %d:\n", i++);
		
	print_route(&(route->route_def));
	if (route->route_def.dst_type == LINK_INTERFACE) {
	    PrintDebug("dst_dev (%p), dst_dev_id (%d), dst_dev_ops(%p), dst_dev_data (%p)\n",
	       	route->dst_dev,
	       	route->dst_dev->dev_id,
	       	(void *)&(route->dst_dev->dev_ops),
	       	route->dst_dev->private_data);
	}
    }

    PrintDebug("\n========Dump routes end ============\n");
}

#endif


/* 
 * A VNET packet is a packed struct with the hashed fields grouped together.
 * This means we can generate the hash from an offset into the pkt struct
 */
static inline uint_t hash_fn(addr_t hdr_ptr) {    
    uint8_t * hdr_buf = (uint8_t *)hdr_ptr;

    return v3_hash_buffer(hdr_buf, VNET_HASH_SIZE);
}

static inline int hash_eq(addr_t key1, addr_t key2) {	
    return (memcmp((uint8_t *)key1, (uint8_t *)key2, VNET_HASH_SIZE) == 0);
}

static int add_route_to_cache(const struct v3_vnet_pkt * pkt, struct route_list * routes) {
    memcpy(routes->hash_buf, pkt->hash_buf, VNET_HASH_SIZE);    

    if (v3_htable_insert(vnet_state.route_cache, (addr_t)routes->hash_buf, (addr_t)routes) == 0) {
	PrintError("VNET/P Core: Failed to insert new route entry to the cache\n");
	return -1;
    }
    
    return 0;
}

static int clear_hash_cache() {
    v3_free_htable(vnet_state.route_cache, 1, 1);
    vnet_state.route_cache = v3_create_htable(0, &hash_fn, &hash_eq);

    return 0;
}

static int look_into_cache(const struct v3_vnet_pkt * pkt, struct route_list ** routes) {
    *routes = (struct route_list *)v3_htable_search(vnet_state.route_cache, (addr_t)(pkt->hash_buf));
   
    return 0;
}


static struct vnet_dev * dev_by_id(int idx) {
    struct vnet_dev * dev = NULL; 

    list_for_each_entry(dev, &(vnet_state.devs), node) {
	int dev_id = dev->dev_id;

	if (dev_id == idx)
	    return dev;
    }

    return NULL;
}

static struct vnet_dev * dev_by_mac(uint8_t * mac) {
    struct vnet_dev * dev = NULL; 
    
    list_for_each_entry(dev, &(vnet_state.devs), node) {
	if (!compare_ethaddr(dev->mac_addr, mac)){
	    return dev;
	}
    }

    return NULL;
}


int v3_vnet_find_dev(uint8_t  * mac) {
    struct vnet_dev * dev = NULL;

    dev = dev_by_mac(mac);

    if(dev != NULL) {
	return dev->dev_id;
    }

    return -1;
}


int v3_vnet_add_route(struct v3_vnet_route route) {
    struct vnet_route_info * new_route = NULL;
    unsigned long flags; 

    new_route = (struct vnet_route_info *)V3_Malloc(sizeof(struct vnet_route_info));
    memset(new_route, 0, sizeof(struct vnet_route_info));

#ifdef CONFIG_DEBUG_VNET
    PrintDebug("VNET/P Core: add_route_entry:\n");
    print_route(&route);
#endif
    
    memcpy(new_route->route_def.src_mac, route.src_mac, ETH_ALEN);
    memcpy(new_route->route_def.dst_mac, route.dst_mac, ETH_ALEN);
    new_route->route_def.src_mac_qual = route.src_mac_qual;
    new_route->route_def.dst_mac_qual = route.dst_mac_qual;
    new_route->route_def.dst_type = route.dst_type;
    new_route->route_def.src_type = route.src_type;
    new_route->route_def.src_id = route.src_id;
    new_route->route_def.dst_id = route.dst_id;

    if (new_route->route_def.dst_type == LINK_INTERFACE) {
	new_route->dst_dev = dev_by_id(new_route->route_def.dst_id);
    }

    if (new_route->route_def.src_type == LINK_INTERFACE) {
	new_route->src_dev = dev_by_id(new_route->route_def.src_id);
    }


    flags = v3_lock_irqsave(vnet_state.lock);

    list_add(&(new_route->node), &(vnet_state.routes));
    clear_hash_cache();

    v3_unlock_irqrestore(vnet_state.lock, flags);
   

#ifdef CONFIG_DEBUG_VNET
    dump_routes();
#endif

    return 0;
}


/* delete all route entries with specfied src or dst device id */ 
static void inline del_routes_by_dev(int dev_id){
    struct vnet_route_info * route = NULL;
    unsigned long flags; 

    flags = v3_lock_irqsave(vnet_state.lock);

    list_for_each_entry(route, &(vnet_state.routes), node) {
	if((route->route_def.dst_type == LINK_INTERFACE &&
	     route->route_def.dst_id == dev_id) ||
	     (route->route_def.src_type == LINK_INTERFACE &&
	      route->route_def.src_id == dev_id)){
	      
	    list_del(&(route->node));
	    list_del(&(route->match_node));
	    V3_Free(route);    
	}
    }

    v3_unlock_irqrestore(vnet_state.lock, flags);
}

/* At the end allocate a route_list
 * This list will be inserted into the cache so we don't need to free it
 */
static struct route_list * match_route(const struct v3_vnet_pkt * pkt) {
    struct vnet_route_info * route = NULL; 
    struct route_list * matches = NULL;
    int num_matches = 0;
    int max_rank = 0;
    struct list_head match_list;
    struct eth_hdr * hdr = (struct eth_hdr *)(pkt->data);
 //   uint8_t src_type = pkt->src_type;
 //   uint32_t src_link = pkt->src_id;

#ifdef CONFIG_DEBUG_VNET
    {
	char dst_str[100];
	char src_str[100];

	mac_to_string(hdr->src_mac, src_str);  
	mac_to_string(hdr->dst_mac, dst_str);
	PrintDebug("VNET/P Core: match_route. pkt: SRC(%s), DEST(%s)\n", src_str, dst_str);
    }
#endif

    INIT_LIST_HEAD(&match_list);
    
#define UPDATE_MATCHES(rank) do {				\
	if (max_rank < (rank)) {				\
	    max_rank = (rank);					\
	    INIT_LIST_HEAD(&match_list);			\
	    							\
	    list_add(&(route->match_node), &match_list);	\
	    num_matches = 1;					\
	} else if (max_rank == (rank)) {			\
	    list_add(&(route->match_node), &match_list);	\
	    num_matches++;					\
	}							\
    } while (0)
    

    list_for_each_entry(route, &(vnet_state.routes), node) {
	struct v3_vnet_route * route_def = &(route->route_def);

/*
	// CHECK SOURCE TYPE HERE
	if ( (route_def->src_type != LINK_ANY) && 
	     ( (route_def->src_type != src_type) || 
	       ( (route_def->src_id != src_link) &&
		 (route_def->src_id != -1)))) {
	    continue;
	}
*/

	if ((route_def->dst_mac_qual == MAC_ANY) &&
	    (route_def->src_mac_qual == MAC_ANY)) {      
	    UPDATE_MATCHES(3);
	}
	
	if (memcmp(route_def->src_mac, hdr->src_mac, 6) == 0) {
	    if (route_def->src_mac_qual != MAC_NOT) {
		if (route_def->dst_mac_qual == MAC_ANY) {
		    UPDATE_MATCHES(6);
		} else if (route_def->dst_mac_qual != MAC_NOT &&
			   memcmp(route_def->dst_mac, hdr->dst_mac, 6) == 0) {
		    UPDATE_MATCHES(8);
		}
	    }
	}
	    
	if (memcmp(route_def->dst_mac, hdr->dst_mac, 6) == 0) {
	    if (route_def->dst_mac_qual != MAC_NOT) {
		if (route_def->src_mac_qual == MAC_ANY) {
		    UPDATE_MATCHES(6);
		} else if ((route_def->src_mac_qual != MAC_NOT) && 
			   (memcmp(route_def->src_mac, hdr->src_mac, 6) == 0)) {
		    UPDATE_MATCHES(8);
		}
	    }
	}
	    
	if ((route_def->dst_mac_qual == MAC_NOT) &&
	    (memcmp(route_def->dst_mac, hdr->dst_mac, 6) != 0)) {
	    if (route_def->src_mac_qual == MAC_ANY) {
		UPDATE_MATCHES(5);
	    } else if ((route_def->src_mac_qual != MAC_NOT) && 
		       (memcmp(route_def->src_mac, hdr->src_mac, 6) == 0)) {     
		UPDATE_MATCHES(7);
	    }
	}
	
	if ((route_def->src_mac_qual == MAC_NOT) &&
	    (memcmp(route_def->src_mac, hdr->src_mac, 6) != 0)) {
	    if (route_def->dst_mac_qual == MAC_ANY) {
		UPDATE_MATCHES(5);
	    } else if ((route_def->dst_mac_qual != MAC_NOT) &&
		       (memcmp(route_def->dst_mac, hdr->dst_mac, 6) == 0)) {
		UPDATE_MATCHES(7);
	    }
	}
	
	// Default route
	if ( (memcmp(route_def->src_mac, hdr->src_mac, 6) == 0) &&
	     (route_def->dst_mac_qual == MAC_NONE)) {
	    UPDATE_MATCHES(4);
	}
    }

    PrintDebug("VNET/P Core: match_route: Matches=%d\n", num_matches);

    if (num_matches == 0) {
	return NULL;
    }

    matches = (struct route_list *)V3_Malloc(sizeof(struct route_list) + 
				(sizeof(struct vnet_route_info *) * num_matches));

    matches->num_routes = num_matches;

    {
	int i = 0;
	list_for_each_entry(route, &match_list, match_node) {
	    matches->routes[i++] = route;
	}
    }

    return matches;
}


int v3_vnet_send_pkt(struct v3_vnet_pkt * pkt, void * private_data) {
    struct route_list * matched_routes = NULL;
    unsigned long flags;
    int i;

#ifdef CONFIG_DEBUG_VNET
   {
	int cpu = V3_Get_CPU();
       PrintDebug("VNET/P Core: cpu %d: pkt (size %d, src_id:%d, src_type: %d, dst_id: %d, dst_type: %d)\n",
		  cpu, pkt->size, pkt->src_id, 
		  pkt->src_type, pkt->dst_id, pkt->dst_type);
       //v3_hexdump(pkt->data, pkt->size, NULL, 0);
   }
#endif

    flags = v3_lock_irqsave(vnet_state.lock);

    vnet_state.stats.rx_bytes += pkt->size;
    vnet_state.stats.rx_pkts++;

    look_into_cache(pkt, &matched_routes);
    if (matched_routes == NULL) {  
	PrintDebug("VNET/P Core: send pkt Looking into routing table\n");
	
	matched_routes = match_route(pkt);
	
      	if (matched_routes) {
	    add_route_to_cache(pkt, matched_routes);
	} else {
	    PrintDebug("VNET/P Core: Could not find route for packet... discards packet\n");
	    v3_unlock_irqrestore(vnet_state.lock, flags);
	    return 0; /* do we return -1 here?*/
	}
    }

    v3_unlock_irqrestore(vnet_state.lock, flags);

    PrintDebug("VNET/P Core: send pkt route matches %d\n", matched_routes->num_routes);

    for (i = 0; i < matched_routes->num_routes; i++) {
	struct vnet_route_info * route = matched_routes->routes[i];
	
        if (route->route_def.dst_type == LINK_EDGE) {
	    struct vnet_brg_dev *bridge = vnet_state.bridge;
            pkt->dst_type = LINK_EDGE;
            pkt->dst_id = route->route_def.dst_id;

    	    if (bridge == NULL || (bridge->active == 0)) {
	        PrintDebug("VNET/P Core: No active bridge to sent data to\n");
		 continue;
    	    }

    	    if(bridge->brg_ops.input(bridge->vm, pkt, bridge->private_data) < 0){
                PrintDebug("VNET/P Core: Packet not sent properly to bridge\n");
                continue;
	    }         
	    vnet_state.stats.tx_bytes += pkt->size;
	    vnet_state.stats.tx_pkts ++;
        } else if (route->route_def.dst_type == LINK_INTERFACE) {
            if (route->dst_dev == NULL || route->dst_dev->active == 0){
	 	PrintDebug("VNET/P Core: No active device to sent data to\n");
	        continue;
            }

	    if(route->dst_dev->dev_ops.input(route->dst_dev->vm, pkt, route->dst_dev->private_data) < 0) {
                PrintDebug("VNET/P Core: Packet not sent properly\n");
                continue;
	    }
	    vnet_state.stats.tx_bytes += pkt->size;
	    vnet_state.stats.tx_pkts ++;
        } else {
            PrintError("VNET/P Core: Wrong dst type\n");
        }
    }
    
    return 0;
}

int v3_vnet_add_dev(struct v3_vm_info * vm, uint8_t * mac, 
		    struct v3_vnet_dev_ops *ops,
		    void * priv_data){
    struct vnet_dev * new_dev = NULL;
    unsigned long flags;

    new_dev = (struct vnet_dev *)V3_Malloc(sizeof(struct vnet_dev)); 

    if (new_dev == NULL) {
	PrintError("Malloc fails\n");
	return -1;
    }
   
    memcpy(new_dev->mac_addr, mac, 6);
    new_dev->dev_ops.input = ops->input;
    new_dev->dev_ops.poll = ops->poll;
    new_dev->private_data = priv_data;
    new_dev->vm = vm;
    new_dev->dev_id = 0;
    new_dev->active = 1;
    new_dev->mode = GUEST_DRIVERN;

    flags = v3_lock_irqsave(vnet_state.lock);

    if (dev_by_mac(mac) == NULL) {
	list_add(&(new_dev->node), &(vnet_state.devs));
	new_dev->dev_id = ++vnet_state.num_devs;
    }

    v3_unlock_irqrestore(vnet_state.lock, flags);

    /* if the device was found previosly the id should still be 0 */
    if (new_dev->dev_id == 0) {
	PrintError("VNET/P Core: Device Already exists\n");
	return -1;
    }

    PrintDebug("VNET/P Core: Add Device: dev_id %d\n", new_dev->dev_id);

    return new_dev->dev_id;
}



int v3_vnet_del_dev(int dev_id){
    struct vnet_dev * dev = NULL;
    unsigned long flags;

    flags = v3_lock_irqsave(vnet_state.lock);
	
    dev = dev_by_id(dev_id);
    if (dev != NULL){
    	list_del(&(dev->node));
	del_routes_by_dev(dev_id);
    }
	
    v3_unlock_irqrestore(vnet_state.lock, flags);

    V3_Free(dev);

    PrintDebug("VNET/P Core: Remove Device: dev_id %d\n", dev_id);

    return 0;
}

int v3_vnet_stat(struct vnet_stat * stats){
	
    stats->rx_bytes = vnet_state.stats.rx_bytes;
    stats->rx_pkts = vnet_state.stats.rx_pkts;
    stats->tx_bytes = vnet_state.stats.tx_bytes;
    stats->tx_pkts = vnet_state.stats.tx_pkts;

    return 0;
}

static void free_devices(){
    struct vnet_dev * dev = NULL; 

    list_for_each_entry(dev, &(vnet_state.devs), node) {
	list_del(&(dev->node));
	V3_Free(dev);
    }
}

static void free_routes(){
    struct vnet_route_info * route = NULL; 

    list_for_each_entry(route, &(vnet_state.routes), node) {
	list_del(&(route->node));
	list_del(&(route->match_node));
	V3_Free(route);
    }
}

int v3_vnet_add_bridge(struct v3_vm_info * vm,
		       struct v3_vnet_bridge_ops * ops,
		       uint8_t type,
		       void * priv_data) {
    unsigned long flags;
    int bridge_free = 0;
    struct vnet_brg_dev * tmp_bridge = NULL;    
    
    flags = v3_lock_irqsave(vnet_state.lock);

    if (vnet_state.bridge == NULL) {
	bridge_free = 1;
	vnet_state.bridge = (void *)1;
    }

    v3_unlock_irqrestore(vnet_state.lock, flags);

    if (bridge_free == 0) {
	PrintError("VNET/P Core: Bridge already set\n");
	return -1;
    }

    tmp_bridge = (struct vnet_brg_dev *)V3_Malloc(sizeof(struct vnet_brg_dev));

    if (tmp_bridge == NULL) {
	PrintError("Malloc Fails\n");
	vnet_state.bridge = NULL;
	return -1;
    }
    
    tmp_bridge->vm = vm;
    tmp_bridge->brg_ops.input = ops->input;
    tmp_bridge->brg_ops.poll = ops->poll;
    tmp_bridge->private_data = priv_data;
    tmp_bridge->active = 1;
    tmp_bridge->mode = GUEST_DRIVERN;
    tmp_bridge->type = type;
	
    /* make this atomic to avoid possible race conditions */
    flags = v3_lock_irqsave(vnet_state.lock);
    vnet_state.bridge = tmp_bridge;
    v3_unlock_irqrestore(vnet_state.lock, flags);

    return 0;
}


int v3_init_vnet() {
    memset(&vnet_state, 0, sizeof(vnet_state));
	
    INIT_LIST_HEAD(&(vnet_state.routes));
    INIT_LIST_HEAD(&(vnet_state.devs));

    vnet_state.num_devs = 0;
    vnet_state.num_routes = 0;

    if (v3_lock_init(&(vnet_state.lock)) == -1){
        PrintError("VNET/P Core: Fails to initiate lock\n");
    }

    vnet_state.route_cache = v3_create_htable(0, &hash_fn, &hash_eq);

    if (vnet_state.route_cache == NULL) {
        PrintError("VNET/P Core: Fails to initiate route cache\n");
        return -1;
    }

    PrintDebug("VNET/P Core is initiated\n");

    return 0;
}


void v3_deinit_vnet(){

    v3_lock_deinit(&(vnet_state.lock));

    free_devices();
    free_routes();

    v3_free_htable(vnet_state.route_cache, 1, 1);
    V3_Free(vnet_state.bridge);
}


