/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National
 * Science Foundation and the Department of Energy.
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org>
 * All rights reserved.
 *
 * Author: Alexander Kudryavtsev <alexk@ispras.ru>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#ifndef __VMM_FW_CFG_H__
#define __VMM_FW_CFG_H__

#ifdef __V3VEE__

struct v3_vm_info;

int v3_fw_cfg_init(struct v3_vm_info *vm);
void v3_delete_fw_cfg(struct v3_vm_info *vm);

#endif

#endif
