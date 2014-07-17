/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_intr.h>
#include <palacios/vmm_config.h>
#include <palacios/vm.h>
#include <palacios/vmm_ctrl_regs.h>
#include <palacios/vmm_lowlevel.h>
#include <palacios/vmm_sprintf.h>
#include <palacios/vmm_extensions.h>
#include <palacios/vmm_timeout.h>
#include <palacios/vmm_options.h>


#ifdef V3_CONFIG_SVM
#include <palacios/svm.h>
#endif
#ifdef V3_CONFIG_VMX
#include <palacios/vmx.h>
#endif

#ifdef V3_CONFIG_CHECKPOINT
#include <palacios/vmm_checkpoint.h>
#endif

/* 
 * The architecture we are running on
 */
v3_cpu_arch_t v3_mach_type = V3_INVALID_CPU;

/* 
 * List of valid CPUs usable by VMM
 */
v3_cpu_arch_t v3_cpu_types[V3_CONFIG_MAX_CPUS];

/*
 * The vcore thread currently executing on each physical core
 *  - NULL if there is no vcore thread currently active
 */
struct v3_core_info * v3_cores_current[V3_CONFIG_MAX_CPUS];

/* 
 * List of vcores currently assigned to each physical core
 */
static struct list_head v3_cores_assigned[V3_CONFIG_MAX_CPUS];

/* 
 * List of VMs currently running
 */
static LIST_HEAD(v3_vm_list);

/*
 * Special lock to protect access to the following global data structures
 *  - v3_cores_assigned
 *  - v3_cpu_types
 *  - v3_vm_list 
 */
static struct {
    v3_spinlock_t lock;
    int           acquired;
} gbl_op_lock;


/*
 * OS interface function hooks
 *  - assigned by host OS during initialization
 */
struct v3_os_hooks    * os_hooks = NULL;


int v3_dbg_enable              = 0;

#ifdef V3_CONFIG_KITTEN
extern void lapic_set_timer_freq(unsigned int hz);
#endif


static void
op_lock_init()
{
    v3_spinlock_init(&(gbl_op_lock.lock));
    gbl_op_lock.acquired = 0;
}


static void
op_lock_deinit()
{
    v3_spinlock_deinit(&(gbl_op_lock.lock));
    gbl_op_lock.acquired = 1;

}

static void
op_lock_acquire()
{
    uint64_t flags = 0;
    int acquired = 0;

    while (!acquired) {
	flags = v3_spin_lock_irqsave(&(gbl_op_lock.lock));
	{
	    if (gbl_op_lock.acquired == 0) {
		gbl_op_lock.acquired = 1;
		acquired             = 1;
	    }
	}
	v3_spin_unlock_irqrestore(&(gbl_op_lock.lock), flags);

	if (!acquired) V3_Yield();
    }

}

static void
op_lock_release()
{
    uint64_t flags = 0;

    flags = v3_spin_lock_irqsave(&(gbl_op_lock.lock));
    {
	gbl_op_lock.acquired = 0;
    }
    v3_spin_unlock_irqrestore(&(gbl_op_lock.lock), flags);
}


static void 
init_cpu(void * arg) 
{
    uint32_t cpu_id = (uint32_t)(addr_t)arg;

#ifdef V3_CONFIG_KITTEN
    lapic_set_timer_freq(1000);
#endif
	
#ifdef V3_CONFIG_SVM
    if (v3_is_svm_capable()) {
	PrintDebug("Machine is SVM Capable\n");
	v3_init_svm_cpu(cpu_id);
	
    } else 
#endif
#ifdef V3_CONFIG_VMX
    if (v3_is_vmx_capable()) {
	PrintDebug("Machine is VMX Capable\n");
	v3_init_vmx_cpu(cpu_id);
	
    } else 
#endif
    {
	PrintError("CPU has no virtualization Extensions\n");
    }	
}


static void
deinit_cpu(void * arg) 
{
    uint32_t cpu_id = (uint32_t)(addr_t)arg;

    switch (v3_cpu_types[cpu_id]) {
#ifdef V3_CONFIG_SVM
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	    PrintDebug("Deinitializing SVM CPU %d\n", cpu_id);
	    v3_deinit_svm_cpu(cpu_id);
	    break;
#endif
#ifdef V3_CONFIG_VMX
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:
	    PrintDebug("Deinitializing VMX CPU %d\n", cpu_id);
	    v3_deinit_vmx_cpu(cpu_id);
	    break;
#endif
	case V3_INVALID_CPU:
	default:
	    PrintError("CPU has no virtualization Extensions\n");
	    break;
    }

}

int 
v3_add_cpu(int cpu_id) 
{
    int ret = 0;

    if (os_hooks == NULL) {
	PrintError("Error Tried to add a CPU to unitialized VMM\n");
	return -1;
    }

    V3_Print("Adding CPU %d\n", cpu_id);

    op_lock_acquire();
    {
	if (v3_cpu_types[cpu_id] != V3_INVALID_CPU) {
	    PrintError("Error: CPU %d is already Active\n", cpu_id);
	    ret = -1;
	} else {
	    os_hooks->call_on_cpu(cpu_id, &init_cpu, (void *)(addr_t)cpu_id);
	}
    }
    op_lock_release();

    return ret;
}

int 
v3_remove_cpu(int cpu_id) 
{
    int ret = 0;
 
    if (os_hooks == NULL) {
	PrintError("Error Tried to remove a CPU from unitialized VMM\n");
	return -1;
    }

    V3_Print("Removing CPU %d\n", cpu_id);


    op_lock_acquire();
    {

	if (!list_empty(&(v3_cores_assigned[cpu_id]))) {
	    PrintError("Error: CPU %d has active VCores\n", cpu_id);
	    ret = -1;
	} else if (v3_cpu_types[cpu_id] == V3_INVALID_CPU) {
	    PrintError("Error: CPU %d is inactive\n", cpu_id);
	    ret = -1;
	} else {
	    os_hooks->call_on_cpu(cpu_id, &deinit_cpu, (void *)(addr_t)cpu_id);
	}
    }
    op_lock_release();

    return ret;
}

int 
Init_V3(struct v3_os_hooks * hooks, 
	char               * cpu_mask, 
	int                  num_cpus,
	char               * options) 
{
    int minor = 0;
    int major = 0;
    int i = 0;

    V3_Print("V3 Print statement to fix a Kitten page fault bug\n");

    /* Initialize op lock */
    op_lock_init();

    /* Set global variables.  */
    os_hooks = hooks;

    /* Determine the global machine type */
    v3_mach_type = V3_INVALID_CPU;

    /* Initialize each cores type/state */
    for (i = 0; i < V3_CONFIG_MAX_CPUS; i++) {
	v3_cpu_types[i]     = V3_INVALID_CPU;
	v3_cores_current[i] = NULL;
	INIT_LIST_HEAD(&(v3_cores_assigned[i]));
    }

    /* Setup options from host OS */
    if (V3_init_options(options) == -1) {
	PrintError("Error parsing VMM options. Aborting Initialization.\n");
	return -1;
    }

    /* Register all the possible device types */
    V3_init_devices();

    /* Register all shadow paging handlers */
    V3_init_shdw_paging();

    /* Register all extensions */
    V3_init_extensions();



#ifdef V3_CONFIG_CHECKPOINT
    V3_init_chkpt_stores();
#endif

    if ((hooks) && (hooks->call_on_cpu)) {

        for (i = 0; i < num_cpus; i++) {
            major = i / 8;
            minor = i % 8;

            if ((cpu_mask == NULL) || (*(cpu_mask + major) & (0x1 << minor))) {
                V3_Print("Initializing VMM extensions on cpu %d\n", i);
                hooks->call_on_cpu(i, &init_cpu, (void *)(addr_t)i);

		if (v3_mach_type == V3_INVALID_CPU) {
		    v3_mach_type = v3_cpu_types[i];
		}   
            }
        }
    }
    
    return 0;
}



int
Shutdown_V3() 
{
    int i;

    op_lock_acquire();
    {
	
	if (!list_empty(&v3_vm_list)) {
	    PrintError("Error: Cannot Shutdown Palacios with Active VMs\n");
	    op_lock_release();
	    return -1;
	} 


	if ((os_hooks) && (os_hooks->call_on_cpu)) {
	    for (i = 0; i < V3_CONFIG_MAX_CPUS; i++) {
		if (v3_cpu_types[i] != V3_INVALID_CPU) {
		    
		    if (!list_empty(&(v3_cores_assigned[i]))) {
			PrintError("ERROR: Invalid VMM state.\n");
			PrintError("\tVCPUs are assigned to core %d, but no VMs are active\n", i);
			op_lock_release();
			return -1;
		    }

		    V3_Call_On_CPU(i, deinit_cpu, (void *)(addr_t)i);
		    //deinit_cpu((void *)(addr_t)i);
		}
	    }
	}
	
    }
    op_lock_release();

    V3_deinit_devices();
    V3_deinit_shdw_paging();

    V3_deinit_extensions();


#ifdef V3_CONFIG_CHECKPOINT
    V3_deinit_chkpt_stores();
#endif


    op_lock_deinit();

    return 0;
}


v3_cpu_arch_t 
v3_get_cpu_type(int cpu_id) 
{
    v3_cpu_arch_t cpu_type = V3_INVALID_CPU;

    op_lock_acquire();
    {
	cpu_type = v3_cpu_types[cpu_id];
    }
    op_lock_release();

    return cpu_type;
}



struct v3_vm_info * 
v3_create_vm(void * cfg, 
	     void * priv_data, 
	     char * name) 
{
    struct v3_vm_info * vm = v3_config_guest(cfg, priv_data);

    if (vm == NULL) {
	PrintError("Could not configure guest\n");
	return NULL;
    }

    V3_Print("CORE 0 RIP=%p\n", (void *)(addr_t)(vm->cores[0].rip));

    if (name == NULL) {
	name = "[V3_VM]";
    } else if (strlen(name) >= 128) {
	PrintError("VM name is too long. Will be truncated to 128 chars.\n");
    }

    memset (vm->name, 0,    128);
    strncpy(vm->name, name, 127);

    op_lock_acquire();
    {
	list_add(&(vm->vm_list_node), &(v3_vm_list));
    }
    op_lock_release();

    return vm;
}



int 
v3_free_vm(struct v3_vm_info * vm) 
{
    int i = 0;
    // deinitialize guest (free memory, etc...)
    

    op_lock_acquire();
    {
	list_del(&(vm->vm_list_node));
    }
    op_lock_release();


    // Mark as dead

    v3_free_vm_devices(vm);

    // free cores
    for (i = 0; i < vm->num_cores; i++) {
	v3_free_core(&(vm->cores[i]));
    }

    // free vm
    v3_free_vm_internal(vm);

    v3_free_config(vm);

    V3_Free(vm);



    return 0;
}


#ifdef V3_CONFIG_HOST_SCHED_EVENTS
#include <interfaces/sched_events.h>
static int 
core_sched_in(struct v3_core_info * core, int cpu) 
{
    v3_cores_current[cpu] = core;
    v3_telemetry_inc_core_counter(core, "CORE_SCHED_IN");

    /* In case we were migrated... */
    if (core->pcpu_id != cpu) {
	V3_Print("Core Migrated from CPU %d to %d\n", 
		 core->pcpu_id, cpu);

	core->pcpu_id = cpu;
    }

    return 0;
}

static int 
core_sched_out(struct v3_core_info * core, int cpu) 
{
    v3_telemetry_inc_core_counter(core, "CORE_SCHED_OUT");

    v3_fpu_deactivate(core);

    v3_cores_current[cpu] = NULL;

    return 0;
}
#endif



/* 
 * This function must be called with the gbl_op_lock acquired
 */
static int 
start_core(void * p)
{
    struct v3_core_info * core = (struct v3_core_info *)p;
    int ret = 0;

#ifdef V3_CONFIG_HOST_SCHED_EVENTS
    v3_hook_core_preemptions(core, core_sched_in, core_sched_out);
#endif

    PrintDebug("virtual core %u (on logical core %u): in start_core (RIP=%p)\n", 
	       core->vcpu_id, core->pcpu_id, (void *)(addr_t)core->rip);

    /* Add VCore to active core lists */
    v3_cores_current[V3_Get_CPU()] = core;
    list_add(&(core->curr_cores_node), &(v3_cores_assigned[V3_Get_CPU()]));
    

    switch (v3_mach_type) {
#ifdef V3_CONFIG_SVM
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	    ret = v3_start_svm_guest(core);
	    break;
#endif
#if V3_CONFIG_VMX
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:
	    ret = v3_start_vmx_guest(core);
	    break;
#endif
	default:
	    PrintError("Attempting to enter a guest on an invalid CPU\n");
	    return -1;
    }

    /* Remove VCore from Active Core lists */
    v3_cores_current[V3_Get_CPU()] = NULL;
    list_del(&(core->curr_cores_node));


#ifdef V3_CONFIG_HOST_SCHED_EVENTS
    v3_unhook_core_preemptions(core, core_sched_in, core_sched_out);
#endif

    return ret;
}


// For the moment very ugly. Eventually we will shift the cpu_mask to an arbitrary sized type...
#define MAX_CORES 32


int 
v3_start_vm(struct v3_vm_info * vm,
	    unsigned int        cpu_mask)
{
    uint8_t * core_mask   = (uint8_t *)&cpu_mask; // This is to make future expansion easier
    uint32_t  avail_cores = 0;
    int       vcore_id    = 0;
    uint32_t i;

    if (vm->run_state != VM_STOPPED) {
        PrintError("VM has already been launched (state=%d)\n", (int)vm->run_state);
        return -1;
    }

    V3_Print("V3 --  Starting VM (%u cores)\n", vm->num_cores);
    V3_Print("CORE 0 RIP=%p\n",                 (void *)(addr_t)(vm->cores[0].rip));


    op_lock_acquire();

    // Check that enough cores are present in the mask to handle vcores
    for (i = 0; i < MAX_CORES; i++) {
	int major = i / 8;
	int minor = i % 8;
	
	if (core_mask[major] & (0x1 << minor)) {
	    if (v3_cpu_types[i] == V3_INVALID_CPU) {
		core_mask[major] &= ~(0x1 << minor);
	    } else {
		avail_cores++;
	    }
	}
    }
    

    if (vm->num_cores > avail_cores) {
	PrintError("Attempted to start a VM with too many cores (vm->num_cores = %d, avail_cores = %d, MAX=%d)\n", 
		   vm->num_cores, avail_cores, MAX_CORES);
	op_lock_release();
	return -1;
    }

    vm->run_state = VM_RUNNING;

    // Spawn off threads for each core. 
    // We work backwards, so that core 0 is always started last.
    for (i = 0, vcore_id = vm->num_cores - 1; (i < MAX_CORES) && (vcore_id >= 0); i++) {
	struct v3_core_info * core            = &(vm->cores[vcore_id]);
	char                * specified_cpu   = v3_cfg_val(core->core_cfg_data, "target_cpu");
	uint32_t              core_idx        = 0;
	int major = 0;
 	int minor = 0;

	if (specified_cpu != NULL) {
	    core_idx = atoi(specified_cpu);
	    
	    if ((core_idx < 0) || (core_idx >= MAX_CORES)) {
		PrintError("Target CPU out of bounds (%d) (MAX_CORES=%d)\n", core_idx, MAX_CORES);
	    }

	    i--; // We reset the logical core idx. Not strictly necessary I guess... 
	} else {
	    core_idx = i;
	}

	major = core_idx / 8;
	minor = core_idx % 8;

	if ((core_mask[major] & (0x1 << minor)) == 0) {
	    PrintError("Logical CPU %d not available for virtual core %d; not started\n",
		       core_idx, vcore_id);

	    if (specified_cpu != NULL) {
		PrintError("CPU was specified explicitly (%d). HARD ERROR\n", core_idx);
		goto err;
	    }

	    continue;
	}

	PrintDebug("Starting virtual core %u on logical core %u\n", 
		   vcore_id, core_idx);
	
	sprintf(core->exec_name, "%s-%u", vm->name, vcore_id);

	PrintDebug("run: core=%u, func=0x%p, arg=0x%p, name=%s\n",
		   core_idx, start_core, core, core->exec_name);

	core->core_run_state = CORE_STOPPED;  // core zero will turn itself on
	core->pcpu_id        = core_idx;
	core->core_thread    = V3_CREATE_THREAD_ON_CPU(core_idx, start_core, core, core->exec_name);

	if (core->core_thread == NULL) {
	    PrintError("Thread launch failed\n");
	    goto err;
	}

	vcore_id--;
    }

    if (vcore_id >= 0) {
	PrintError("Error starting VM: Not enough available CPU cores\n");
	goto err;
    }

    op_lock_release();
    return 0;

 err:
    op_lock_release();
    v3_stop_vm(vm);
    return -1; 
}


int 
v3_reset_vm_core(struct v3_core_info * core, 
		 addr_t                rip) 
{
    int ret = 0;
    
    switch (v3_cpu_types[core->pcpu_id]) {
#ifdef V3_CONFIG_SVM
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	    PrintDebug("Resetting SVM Guest CPU %d\n", core->vcpu_id);

	    ret = v3_reset_svm_vm_core(core, rip);

	    break;
#endif
#ifdef V3_CONFIG_VMX
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:
	    PrintDebug("Resetting VMX Guest CPU %d\n", core->vcpu_id);

	    ret = v3_reset_vmx_vm_core(core, rip);

	    break;
#endif
	case V3_INVALID_CPU:
	default:
	    PrintError("CPU has no virtualization Extensions\n");

	    ret = -1;

	    break;
    }

    return ret;
}



/* move a virtual core to different physical core */
int 
v3_move_vm_core(struct v3_vm_info * vm,
		int                 vcore_id, 
		int                 target_cpu) 
{
    struct v3_core_info * core = NULL;
    
    if ( (vcore_id <  0) || 
	 (vcore_id >= vm->num_cores) ) {
	PrintError("Attempted to migrate invalid virtual core (%d)\n", vcore_id);
	return -1;
    }


    core = &(vm->cores[vcore_id]);

    if (core->core_thread == NULL) {
	PrintError("Attempted to migrate a core without a valid thread context\n");
	return -1;
    }

    op_lock_acquire();

    if (v3_cpu_types[target_cpu] == V3_INVALID_CPU) {
	PrintError("Attempted to migrate Vcore to Invalid Physical CPU (%d)\n", 
		   target_cpu);
	op_lock_release();
	return -1;
    }

    while (v3_raise_barrier(vm, NULL) == -1);

    if (target_cpu == core->pcpu_id) {
	PrintError("Attempted to migrate to local core (%d)\n", target_cpu);

	// well that was pointless
	v3_lower_barrier(vm);
	op_lock_release();
	return 0;
    }


    V3_Print("Performing Migration from %d to %d\n", core->pcpu_id, target_cpu);

    // Double check that we weren't preemptively migrated
    if (target_cpu != core->pcpu_id) {    
	V3_Print("Moving Core\n");

#ifdef V3_CONFIG_VMX
	switch (v3_cpu_types[core->pcpu_id]) {
	    case V3_VMX_CPU:
	    case V3_VMX_EPT_CPU:
	    case V3_VMX_EPT_UG_CPU:
		PrintDebug("Flushing VMX Guest CPU %d\n", core->vcpu_id);
		V3_Call_On_CPU(core->pcpu_id, (void (*)(void *))v3_flush_vmx_vm_core, (void *)core);
		break;
	    default:
		break;
	}
#endif


	/* 
	 * Request Host scheduler to Move the thread 
	 */
	if (V3_MOVE_THREAD_TO_CPU(target_cpu, core->core_thread) != 0) {
	    PrintError("Failed to move Vcore %d to CPU %d\n", 
		       core->vcpu_id, target_cpu);

	    v3_lower_barrier(vm);
	    op_lock_release();
	    return -1;
	} 

	
	list_move(&(core->curr_cores_node), &(v3_cores_assigned[target_cpu]));
    }


    v3_lower_barrier(vm);
    op_lock_release();

    return 0;
}



int 
v3_stop_vm(struct v3_vm_info * vm) 
{

    if ((vm->run_state != VM_RUNNING) && 
	(vm->run_state != VM_SIMULATING)) {
	PrintError("Tried to stop VM in invalid runstate (%d)\n", vm->run_state);
	return -1;
    }

    vm->run_state = VM_STOPPED;



    // Sanity check to catch any weird execution states
    if (v3_wait_for_barrier(vm, NULL) == 0) {
	v3_lower_barrier(vm);
    }
    
    // XXX force exit all cores via a cross call/IPI XXX

    while (1) {
	int still_running = 0;
	int i = 0;

	for (i = 0; i < vm->num_cores; i++) {
	    if (vm->cores[i].core_run_state != CORE_STOPPED) {
		still_running = 1;
	    }
	}

	if (still_running == 0) {
 	    break;
	}

	v3_yield(NULL, -1);
    }
    
    V3_Print("VM stopped. Returning\n");

    return 0;
}


int 
v3_pause_vm(struct v3_vm_info * vm) 
{
    if (vm->run_state != VM_RUNNING) {
	PrintError("Tried to pause a VM that was not running\n");
	return -1;
    }

    while (v3_raise_barrier(vm, NULL) == -1);

    vm->run_state = VM_PAUSED;

    return 0;
}


int 
v3_continue_vm(struct v3_vm_info * vm) 
{
    if (vm->run_state != VM_PAUSED) {
	PrintError("Tried to continue a VM that was not paused\n");
	return -1;
    }

    vm->run_state = VM_RUNNING;

    v3_lower_barrier(vm);
    
    return 0;
}



static int 
sim_callback(struct v3_core_info * core, 
	     void                * private_data) 
{
    struct v3_bitmap * timeout_map = private_data;

    v3_bitmap_set(timeout_map, core->vcpu_id);
    
    V3_Print("Simulation callback activated (guest_rip=%p)\n", (void *)core->rip);

    while (v3_bitmap_check(timeout_map, core->vcpu_id) == 1) {
	v3_yield(NULL, -1);
    }

    return 0;
}




int 
v3_simulate_vm(struct v3_vm_info * vm, 
	       unsigned int        msecs) 
{
    struct v3_bitmap timeout_map;
    int              all_blocked = 0;
    uint64_t         cycles      = 0;
    uint64_t         cpu_khz     = V3_CPU_KHZ();
    int i = 0;

    if (vm->run_state != VM_PAUSED) {
	PrintError("VM must be paused before simulation begins\n");
	return -1;
    }

    /* AT this point VM is paused */
    
    // initialize bitmap
    v3_bitmap_init(&timeout_map, vm->num_cores);




    // calculate cycles from msecs...
    // IMPORTANT: Floating point not allowed.
    cycles = (msecs * cpu_khz);
    


    V3_Print("Simulating %u msecs (%llu cycles) [CPU_KHZ=%llu]\n", msecs, cycles, cpu_khz);

    // set timeout
    
    for (i = 0; i < vm->num_cores; i++) {
	if (v3_add_core_timeout(&(vm->cores[i]), cycles, sim_callback, &timeout_map) == -1) {
	    PrintError("Could not register simulation timeout for core %d\n", i);
	    return -1;
	}
    }

    V3_Print("timeouts set on all cores\n ");

    
    // Run the simulation
//    vm->run_state = VM_SIMULATING;
    vm->run_state = VM_RUNNING;
    v3_lower_barrier(vm);


    V3_Print("Barrier lowered: We are now Simulating!!\n");

    // block until simulation is complete    
    while (all_blocked == 0) {
	all_blocked = 1;

	for (i = 0; i < vm->num_cores; i++) {
	    if (v3_bitmap_check(&timeout_map, i)  == 0) {
		all_blocked = 0;
	    }
	}

	if (all_blocked == 1) {
	    break;
	}

	v3_yield(NULL, -1);
    }


    V3_Print("Simulation is complete\n");

    // Simulation is complete
    // Reset back to PAUSED state

    v3_raise_barrier_nowait(vm, NULL);
    vm->run_state = VM_PAUSED;
    
    v3_bitmap_reset(&timeout_map);

    v3_wait_for_barrier(vm, NULL);

    return 0;

}

#ifdef V3_CONFIG_CHECKPOINT
#include <palacios/vmm_checkpoint.h>

int 
v3_save_vm(struct v3_vm_info * vm, char * store, char * url) 
{
    return v3_chkpt_save_vm(vm, store, url);
}


int 
v3_load_vm(struct v3_vm_info * vm, char * store, char * url) 
{
    return v3_chkpt_load_vm(vm, store, url);
}

#ifdef V3_CONFIG_LIVE_MIGRATION
int 
v3_send_vm(struct v3_vm_info * vm, char * store, char * url) 
{
    return v3_chkpt_send_vm(vm, store, url);
}


int 
v3_receive_vm(struct v3_vm_info * vm, char * store, char * url) 
{
    return v3_chkpt_receive_vm(vm, store, url);
}
#endif

#endif



#ifdef __V3_32BIT__

v3_cpu_mode_t 
v3_get_host_cpu_mode() 
{
    uint32_t        cr4_val;
    struct cr4_32 * cr4;

    __asm__ (
	     "movl %%cr4, %0; "
	     : "=r"(cr4_val) 
	     );

    
    cr4 = (struct cr4_32 *)&(cr4_val);

    if (cr4->pae == 1) {
	return PROTECTED_PAE;
    } else {
	return PROTECTED;
    }
}

#elif __V3_64BIT__

v3_cpu_mode_t 
v3_get_host_cpu_mode() 
{
    return LONG;
}

#endif 





void 
v3_yield_cond(struct v3_core_info * core,
	      int                   usec) 
{
    uint64_t cur_cycle = 0;


    cur_cycle = v3_get_host_time(&core->time_state);
    v3_telemetry_inc_core_counter(core, "YIELD_COND");


    if (cur_cycle > (core->yield_start_cycle + core->vm_info->yield_cycle_period)) {
	v3_telemetry_inc_core_counter(core, "YIELD_COND triggered");

	/*
       V3_Print("Conditional Yield (cur_cyle=%p, start_cycle=%p, period=%p)\n", 
	           (void *)cur_cycle, (void *)info->yield_start_cycle, 
		   (void *)info->vm_info->yield_cycle_period);
	*/

	if (usec < 0) { 
	    V3_Yield();
	} else {
	    V3_Sleep(usec);
	}

	//	v3_fpu_load(info);

        core->yield_start_cycle +=  core->vm_info->yield_cycle_period;
    }

}


/* 
 * unconditional cpu yield 
 * if the yielding thread is a guest context, the guest quantum is reset on resumption 
 * Non guest context threads should call this function with a NULL argument
 *
 * usec <0  => the non-timed yield is used
 * usec >=0 => the timed yield is used, which also usually implies interruptible
 */ 
void 
v3_yield(struct v3_core_info * core,
	 int                   usec) 
{
    

    if (usec < 0) { 
	V3_Yield();
    } else {
	V3_Sleep(usec);
    }

    if (core) {
	//	v3_fpu_load(core);
	//        core->yield_start_cycle = ;
    }
}




void 
v3_print_cond(const char * fmt, ...) 
{
    if (v3_dbg_enable == 1) {
	char    buf[2048];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, 2048, fmt, ap);
	va_end(ap);

	V3_Print("%s", buf);
    }    
}



void 
v3_interrupt_cpu(struct v3_vm_info * vm,
		 int                 logical_cpu, 
		 int                 vector) 
{
    extern struct v3_os_hooks * os_hooks;

    if ((os_hooks) && (os_hooks)->interrupt_cpu) {
	(os_hooks)->interrupt_cpu(vm, logical_cpu, vector);
    }
}



int 
v3_vm_enter(struct v3_core_info * core) 
{
    switch (v3_mach_type) {
#ifdef V3_CONFIG_SVM
	case V3_SVM_CPU:
	case V3_SVM_REV3_CPU:
	    return v3_svm_enter(core);
	    break;
#endif
#if V3_CONFIG_VMX
	case V3_VMX_CPU:
	case V3_VMX_EPT_CPU:
	case V3_VMX_EPT_UG_CPU:
	    return v3_vmx_enter(core);
	    break;
#endif
	default:
	    PrintError("Attemping to enter a guest on an invalid CPU\n");
	    return -1;
    }
}


struct v3_core_info * 
v3_get_current_core( void ) {
    return v3_cores_current[V3_Get_CPU()];
}
