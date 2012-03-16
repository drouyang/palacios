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
 * Based on QEMU implementation.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm_fw_cfg.h>
#include <palacios/vmm_mem.h>
#include <palacios/vmm.h>
#include <palacios/vm_guest.h>

#define FW_CFG_CTL_PORT     0x510
#define FW_CFG_DATA_PORT    0x511

#define FW_CFG_SIGNATURE        0x00
#define FW_CFG_ID               0x01
#define FW_CFG_UUID             0x02
#define FW_CFG_RAM_SIZE         0x03
#define FW_CFG_NOGRAPHIC        0x04
#define FW_CFG_NB_CPUS          0x05
#define FW_CFG_MACHINE_ID       0x06
#define FW_CFG_KERNEL_ADDR      0x07
#define FW_CFG_KERNEL_SIZE      0x08
#define FW_CFG_KERNEL_CMDLINE   0x09
#define FW_CFG_INITRD_ADDR      0x0a
#define FW_CFG_INITRD_SIZE      0x0b
#define FW_CFG_BOOT_DEVICE      0x0c
#define FW_CFG_NUMA             0x0d
#define FW_CFG_BOOT_MENU        0x0e
#define FW_CFG_MAX_CPUS         0x0f
#define FW_CFG_KERNEL_ENTRY     0x10
#define FW_CFG_KERNEL_DATA      0x11
#define FW_CFG_INITRD_DATA      0x12
#define FW_CFG_CMDLINE_ADDR     0x13
#define FW_CFG_CMDLINE_SIZE     0x14
#define FW_CFG_CMDLINE_DATA     0x15
#define FW_CFG_SETUP_ADDR       0x16
#define FW_CFG_SETUP_SIZE       0x17
#define FW_CFG_SETUP_DATA       0x18
#define FW_CFG_FILE_DIR         0x19

#define FW_CFG_FILE_FIRST       0x20
#define FW_CFG_FILE_SLOTS       0x10
#define FW_CFG_MAX_ENTRY        (FW_CFG_FILE_FIRST+FW_CFG_FILE_SLOTS)

#define FW_CFG_WRITE_CHANNEL    0x4000
#define FW_CFG_ARCH_LOCAL       0x8000
#define FW_CFG_ENTRY_MASK       ~(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL)

#define FW_CFG_ACPI_TABLES (FW_CFG_ARCH_LOCAL + 0)
#define FW_CFG_SMBIOS_ENTRIES (FW_CFG_ARCH_LOCAL + 1)
#define FW_CFG_IRQ0_OVERRIDE (FW_CFG_ARCH_LOCAL + 2)
#define FW_CFG_E820_TABLE (FW_CFG_ARCH_LOCAL + 3)
#define FW_CFG_HPET (FW_CFG_ARCH_LOCAL + 4)

#define FW_CFG_INVALID          0xffff

typedef void (*cfg_cb)(void *opaque, uint8_t *data);

struct cfg_entry {
    uint32_t len;
    uint8_t *data;
    void *callback_opaque;
    cfg_cb callback;
};

struct cfg_state {
    struct cfg_entry entries[2][FW_CFG_MAX_ENTRY];
    uint16_t cur_entry;
    uint32_t cur_offset;
};

static int fw_cfg_add_bytes(struct cfg_state *s, uint16_t key, uint8_t *data, uint32_t len)
{
    int arch = !!(key & FW_CFG_ARCH_LOCAL);

    key &= FW_CFG_ENTRY_MASK;

    if (key >= FW_CFG_MAX_ENTRY)
        return 0;

    s->entries[arch][key].data = data;
    s->entries[arch][key].len = len;

    return 1;
}

static int fw_cfg_add_i16(struct cfg_state *s, uint16_t key, uint16_t value)
{
    uint16_t *copy;

    copy = V3_Malloc(sizeof(value));
    *copy = value;
    return fw_cfg_add_bytes(s, key, (uint8_t *)copy, sizeof(value));
}
static int fw_cfg_add_i32(struct cfg_state *s, uint16_t key, uint32_t value)
{
    uint32_t *copy;

    copy = V3_Malloc(sizeof(value));
    *copy = value;
    return fw_cfg_add_bytes(s, key, (uint8_t *)copy, sizeof(value));
}
static int fw_cfg_add_i64(struct cfg_state *s, uint16_t key, uint64_t value)
{
    uint64_t *copy;

    copy = V3_Malloc(sizeof(value));
    *copy = value;
    return fw_cfg_add_bytes(s, key, (uint8_t *)copy, sizeof(value));
}

static int fw_cfg_ctl_read(struct guest_info *core, ushort_t port, void *src, uint_t length, void *priv_data) {
    return length;
}
static int fw_cfg_ctl_write(struct guest_info *core, ushort_t port, void *src, uint_t length, void *priv_data) {
    V3_ASSERT(length == 2);
    struct cfg_state * s = (struct cfg_state *)priv_data;
    uint16_t key = *(uint16_t*)src;
    int ret;

    s->cur_offset = 0;
    if ((key & FW_CFG_ENTRY_MASK) >= FW_CFG_MAX_ENTRY) {
        s->cur_entry = FW_CFG_INVALID;
        ret = 0;
    } else {
        s->cur_entry = key;
        ret = 1;
    }

    return length;
}
static int fw_cfg_data_read(struct guest_info *core, ushort_t port, void *src, uint_t length, void *priv_data) {
    V3_ASSERT(length == 1);
    struct cfg_state * s = (struct cfg_state *)priv_data;
    int arch = !!(s->cur_entry & FW_CFG_ARCH_LOCAL);
    struct cfg_entry *e = &s->entries[arch][s->cur_entry & FW_CFG_ENTRY_MASK];
    uint8_t ret;

    if (s->cur_entry == FW_CFG_INVALID || !e->data || s->cur_offset >= e->len)
        ret = 0;
    else
        ret = e->data[s->cur_offset++];

    *(uint8_t*)src = ret;

    return length;
}
static int fw_cfg_data_write(struct guest_info *core, ushort_t port, void *src, uint_t length, void *priv_data) {
    V3_ASSERT(length == 1);
    struct cfg_state * s = (struct cfg_state *)priv_data;
    int arch = !!(s->cur_entry & FW_CFG_ARCH_LOCAL);
    struct cfg_entry *e = &s->entries[arch][s->cur_entry & FW_CFG_ENTRY_MASK];

    if (s->cur_entry & FW_CFG_WRITE_CHANNEL && e->callback &&
        s->cur_offset < e->len) {
        e->data[s->cur_offset++] = *(uint8_t*)src;
        if (s->cur_offset == e->len) {
            e->callback(e->callback_opaque, e->data);
            s->cur_offset = 0;
        }
    }
    return length;
}

#define E820_MAX_COUNT 128
struct e820_entry_packed {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));
struct e820_table {
    uint32_t count;
    struct e820_entry_packed entry[E820_MAX_COUNT];
} __attribute__((packed)) __attribute((__aligned__(4)));

static struct e820_table *e820_populate(struct v3_vm_info *vm) {
    struct v3_e820_entry *e;
    struct e820_table *e820;
    int i = 0;

    if(vm->mem_map.e820_count > E820_MAX_COUNT) {
        PrintError("Too much E820 table entries! (max is %d)\n", E820_MAX_COUNT);
        return NULL;
    }
    e820 = V3_Malloc(sizeof(*e820));
    if(!e820) {
        PrintError("Out of memory!\n");
        return NULL;
    }
    e820->count = vm->mem_map.e820_count;
    list_for_each_entry(e, &vm->mem_map.e820_list, list) {
        e820->entry[i].addr = e->addr;
        e820->entry[i].size = e->size;
        e820->entry[i].type = e->type;
        ++i;
    }
    return e820;
}

int v3_fw_cfg_init(struct v3_vm_info *vm) {

    struct cfg_state *s;
    struct e820_table *e820 = e820_populate(vm);
    if(!e820) {
        PrintError("Failed to populate E820 for FW interface!\n");
        return -1;
    }

#ifdef V3_CONFIG_BOCHSBIOS
/* E820 location in HVM virtual address space. Taken from VMXASSIST. */
#define HVM_E820_PAGE        0x00090000
#define HVM_E820_NR_OFFSET   0x000001E8
#define HVM_E820_OFFSET      0x000002D0
    // Copy E820 to BIOS. See rombios.c, copy_e820_table function.
    addr_t e820_ptr = (addr_t)V3_VAddr((void*)(vm->mem_map.base_region.host_addr + HVM_E820_PAGE));

    *(uint16_t*)(e820_ptr + HVM_E820_NR_OFFSET) = e820->count;
    memcpy((void*)(e820_ptr + HVM_E820_OFFSET), &e820->entry[0], sizeof(e820->entry[0]) * e820->count);
    V3_Free(e820);
    return 0;
#endif
    // else, we have SEABIOS.

    s = V3_Malloc(sizeof(*s));
    memset(s, 0x00, sizeof(*s));

    int ret = 0;
    ret |= v3_hook_io_port(vm, FW_CFG_CTL_PORT, fw_cfg_ctl_read, &fw_cfg_ctl_write, s);
    ret |= v3_hook_io_port(vm, FW_CFG_DATA_PORT, fw_cfg_data_read, &fw_cfg_data_write, s);

    if(ret != 0) {
        V3_Free(e820);
        V3_Free(s);
        PrintError("Failed to hook FW CFG ports!\n");
        return -1;
    }

    fw_cfg_add_bytes(s, FW_CFG_SIGNATURE, (uint8_t *)"QEMU", 4);
    //fw_cfg_add_bytes(s, FW_CFG_UUID, qemu_uuid, 16);
    fw_cfg_add_i16(s, FW_CFG_NOGRAPHIC, /*(uint16_t)(display_type == DT_NOGRAPHIC)*/0);
    fw_cfg_add_i16(s, FW_CFG_NB_CPUS, (uint16_t)vm->num_cores);
    fw_cfg_add_i16(s, FW_CFG_MAX_CPUS, (uint16_t)vm->num_cores);
    fw_cfg_add_i16(s, FW_CFG_BOOT_MENU, (uint16_t)1);
    //fw_cfg_bootsplash(s);

    fw_cfg_add_i32(s, FW_CFG_ID, 1);
    fw_cfg_add_i64(s, FW_CFG_RAM_SIZE, (uint64_t)vm->mem_size / (1024*1024));

    //fw_cfg_add_bytes(fw_cfg, FW_CFG_ACPI_TABLES, (uint8_t *)acpi_tables,
    //       acpi_tables_len);

    fw_cfg_add_i32(s, FW_CFG_IRQ0_OVERRIDE, 1);

    /*smbios_table = smbios_get_table(&smbios_len);
    if (smbios_table)
        fw_cfg_add_bytes(fw_cfg, FW_CFG_SMBIOS_ENTRIES,
                         smbios_table, smbios_len);*/

    fw_cfg_add_bytes(s, FW_CFG_E820_TABLE, (uint8_t *)e820,
                     sizeof(*e820));

    /*fw_cfg_add_bytes(fw_cfg, FW_CFG_HPET, (uint8_t *)&hpet_cfg,
                     sizeof(struct hpet_fw_config));*/

    if(vm->num_nodes != 0) {
        int i, j;
        uint64_t *numa_fw_cfg = V3_Malloc((1 + vm->num_cores + vm->num_nodes) * 8);
        uint64_t core_to_node[vm->num_cores];
        memset(numa_fw_cfg, 0, (1 + vm->num_cores + vm->num_nodes) * 8);
        numa_fw_cfg[0] = vm->num_nodes;
        for (i = 0; i < vm->num_cores; i++) {
            for (j = 0; j < vm->num_nodes; j++) {
                if (vm->node_cpumask[j] & (1 << i)) {
                    core_to_node[i] = j;
                    break;
                }
            }
        }

        memcpy(numa_fw_cfg + 1, core_to_node, sizeof(core_to_node));
        uint64_t node_mem[vm->num_nodes];
        memset(node_mem, 0, sizeof(node_mem));
        struct v3_e820_entry *e, *ep;
        uint64_t start, end = 0;
        int node;

        // Ranges for one node can only be consequent. List is sorted by address.
        e = list_first_entry(&vm->mem_map.e820_list, struct v3_e820_entry, list);
        node = e->node;
        start = e->addr;
        list_for_each_entry(e, &vm->mem_map.e820_list, list) {
            if(e->node != node) {
                end = e->addr;
                node_mem[node] = end - start;
                node = e->node;
                start = end;
            }
            ep = e;
        }
        node_mem[node] = ep->addr + ep->size - start;

        PrintDebug("Node configuration is:\n");
        for (i = 0; i < vm->num_nodes; i++) {
            PrintDebug("  Node %d: CPUs: ", i);
            for(j = 0; j < vm->num_cores; ++j) {
                if(vm->node_cpumask[i] & (1 << j))
                    PrintDebug("%d ", j);
            }
            PrintDebug("Memory: 0x%llx bytes.\n", node_mem[i]);
            numa_fw_cfg[vm->num_cores + 1 + i] = node_mem[i];
        }
        fw_cfg_add_bytes(s, FW_CFG_NUMA, (uint8_t *)numa_fw_cfg,
                (1 + vm->num_cores + vm->num_nodes) * 8);
    }

    vm->fw_cfg_state = s;
    return 0;
}

void v3_delete_fw_cfg(struct v3_vm_info *vm) {
    struct cfg_state *s = (struct cfg_state*)vm->fw_cfg_state;
    int i, j;
    for(i = 0; i < 2; ++i)
        for(j = 0; j < FW_CFG_MAX_ENTRY; ++j) {
            if(s->entries[i][j].data != NULL)
                V3_Free(s->entries[i][j].data);
        }
    V3_Free(s);
    vm->fw_cfg_state = NULL;
}
