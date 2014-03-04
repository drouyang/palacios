#include <palacios/vmm.h>
#include <palacios/vmm_sem.h>
#include <palacios/vmm_lowlevel.h>


extern struct v3_os_hooks * os_hooks;


int v3_sem_init(v3_sem_t * sem, int val) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->sem_alloc);

    *sem = (addr_t)(os_hooks->sem_alloc(val));
    if (!(*sem)) {
        return -1;
    }
    return 0;
}


void v3_sem_deinit(v3_sem_t * sem) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->sem_free);

    os_hooks->sem_free((void *)*sem);
    *sem = 0;
}

void v3_sem_up(v3_sem_t sem) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->sem_up);

    os_hooks->sem_up((void *)sem);
}

void v3_sem_down(v3_sem_t sem) {
    V3_ASSERT(os_hooks);
    V3_ASSERT(os_hooks->sem_down);

    os_hooks->sem_down((void *)sem);
}
