#include <geekos/vmm_stubs.h>
#include <palacios/vmm.h>
#include <geekos/debug.h>
#include <geekos/serial.h>


#define SPEAKER_PORT 0x61




inline void VM_Out_Byte(ushort_t port, uchar_t value)
{
    __asm__ __volatile__ (
	"outb %b0, %w1"
	:
	: "a" (value), "Nd" (port)
    );
}

/*
 * Read a byte from an I/O port.
 */
inline uchar_t VM_In_Byte(ushort_t port)
{
    uchar_t value;

    __asm__ __volatile__ (
	"inb %w1, %b0"
	: "=a" (value)
	: "Nd" (port)
    );

    return value;
}



int IO_Read(ushort_t port, void * dst, uint_t length) {
  uchar_t * iter = dst;
  uint_t i;

  for (i = 0; i < length; i++) {
    *iter = VM_In_Byte(port);    
    iter++;
  }
  
  return 0;
}



int IO_Write(ushort_t port, void * src, uint_t length) {
  uchar_t * iter = src;
  uint_t i;


  for (i = 0; i < length; i++) {
    VM_Out_Byte(port, *iter);    
    iter++;
  }

  return 0;
}



int IO_Write_to_Serial(ushort_t port, void * src, uint_t length) {
  PrintBoth("Output from Guest on port %d (0x%x) Length=%d\n", port, port, length);
  switch (length) {

  case 1:
    PrintBoth(">0x%.2x\n", *(char*)src);
    break;
  case 2:
    PrintBoth(">0x%.4x\n", *(ushort_t*)src);
    break;
  case 4:
    PrintBoth(">0x%.8x\n", *(uint_t*)src);
    break;
  default:
    break;
  }

  //  SerialMemDump(src, length);
  return length;
}



void BuzzVM()
{
  int x;
  int j;
  unsigned char init;

#if 0  
  __asm__ __volatile__ (
    "popf"
    );
    
#endif
    
  PrintBoth("Starting To Buzz\n");

  init=VM_In_Byte(SPEAKER_PORT);

  while (1) {
    VM_Out_Byte(SPEAKER_PORT, init|0x2);
    for (j=0;j<1000000;j++) { 
      x+=j;
    }
    VM_Out_Byte(SPEAKER_PORT, init);
    for (j=0;j<1000000;j++) { 
      x+=j;
    }
  }
}






int RunVMM() {

    struct vmm_os_hooks os_hooks;
    struct vmm_ctrl_ops vmm_ops;
    struct guest_info vm_info;
    addr_t rsp;
    addr_t rip;

    memset(&os_hooks, 0, sizeof(struct vmm_os_hooks));
    memset(&vmm_ops, 0, sizeof(struct vmm_ctrl_ops));
    memset(&vm_info, 0, sizeof(struct guest_info));

    os_hooks.print_debug = &PrintBoth;
    os_hooks.print_info = &Print;
    os_hooks.print_trace = &SerialPrint;
    os_hooks.allocate_pages = &Allocate_VMM_Pages;
    os_hooks.free_page = &Free_VMM_Page;
    os_hooks.malloc = &VMM_Malloc;
    os_hooks.free = &VMM_Free;
    os_hooks.vaddr_to_paddr = &Identity;
    os_hooks.paddr_to_vaddr = &Identity;


    //   DumpGDT();
    Init_VMM(&os_hooks, &vmm_ops);
  
    init_shadow_map(&(vm_info.mem_map));
    init_shadow_page_state(&(vm_info.shdw_pg_state));
    vm_info.page_mode = SHADOW_PAGING;

    vm_info.cpu_mode = REAL;

    init_vmm_io_map(&(vm_info.io_map));

    
    if (0) {
      
      //    add_shared_mem_range(&(vm_info.mem_layout), 0, 0x800000, 0x10000);    
      //    add_shared_mem_range(&(vm_info.mem_layout), 0, 0x1000000, 0);
      
      rip = (ulong_t)(void*)&BuzzVM;
      //  rip -= 0x10000;
      //    rip = (addr_t)(void*)&exit_test;
      //  rip -= 0x2000;
      vm_info.rip = rip;
      rsp = (addr_t)Alloc_Page();
      
      vm_info.vm_regs.rsp = (rsp +4092 );// - 0x2000;
      
            
    } else {
      //add_shared_mem_range(&(vm_info.mem_layout), 0x0, 0x1000, 0x100000);
      //      add_shared_mem_range(&(vm_info.mem_layout), 0x0, 0x100000, 0x0);
      
      shadow_region_t *ent = Malloc(sizeof(shadow_region_t));;
      init_shadow_region_physical(ent,0,0x100000,GUEST_REGION_PHYSICAL_MEMORY,
				  0x100000, HOST_REGION_PHYSICAL_MEMORY);
      add_shadow_region(&(vm_info.mem_map),ent);

      hook_io_port(&(vm_info.io_map), 0x61, &IO_Read, &IO_Write);
      hook_io_port(&(vm_info.io_map), 0x05, &IO_Read, &IO_Write_to_Serial);
      
      /*
      vm_info.cr0 = 0;
      vm_info.cs.base=0xf000;
      vm_info.cs.limit=0xffff;
      */
      //vm_info.rip = 0xfff0;

      vm_info.rip = 0;
      vm_info.vm_regs.rsp = 0x0;
    }

    PrintBoth("Initializing Guest (eip=0x%.8x) (esp=0x%.8x)\n", (uint_t)vm_info.rip,(uint_t)vm_info.vm_regs.rsp);
    (vmm_ops).init_guest(&vm_info);
    PrintBoth("Starting Guest\n");
    (vmm_ops).start_guest(&vm_info);

    return 0;

}
