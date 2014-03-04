#ifndef __VMM_SEM_H__
#define __VMM_SEM_H__

#ifdef __V3VEE__
#include <palacios/vmm_types.h>

typedef addr_t v3_sem_t;

int v3_sem_init(v3_sem_t * sem, int val);
void v3_sem_deinit(v3_sem_t * sem);


void v3_sem_up(v3_sem_t sem);
void v3_sem_down(v3_sem_t sem);

#endif

#endif
