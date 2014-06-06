/* NUMA topology 
 * (c) Jack Lange, 2013
 */


#ifndef __NUMA_H__
#define __NUMA_H__


/* 
 * Initialize Palacios NUMA interface 
 */
int 
palacios_init_numa( void );

/*
 * Returns the number of NUMA zones on the local system
 */
int 
numa_num_nodes(void );

/* 
 * Returns the NUMA zone containing a CPU
 *  - cpu_id  : The CPU to query
 */
int numa_cpu_to_node(int cpu_id);

/* 
 * Returns the NUMA zone containing a given physical address
 *  - phys_addr  : Physical Address to query
 */
int 
numa_addr_to_node(uintptr_t phys_addr);


/* 
 * Returns the NUMA distance (as reported via ACPI) between two NUMA zones
 */
int 
numa_get_distance(int node1, int node2);



#endif

