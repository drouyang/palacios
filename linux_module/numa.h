/* NUMA topology 
 * (c) Jack Lange, 2013
 */


#ifndef __NUMA_H__
#define __NUMA_H__

/* FUCK YOU LINUX */
int create_numa_topology_from_user(void __user * argp);

void free_numa_topology();

int numa_num_nodes();
int numa_cpu_to_node(int cpu);
int numa_addr_to_node(uintptr_t phys_addr);
int numa_get_distance(int node1, int node2);



#endif
