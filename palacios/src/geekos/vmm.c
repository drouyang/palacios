#include <geekos/vmm.h>
#include <geekos/svm.h>
#include <geekos/vmx.h>


uint_t vmm_cpu_type;




struct vmm_os_hooks * os_hooks = NULL;


void Init_VMM(struct vmm_os_hooks * hooks) {
  vmm_cpu_type = VMM_INVALID_CPU;

  os_hooks = hooks;

  PrintDebug("sizeof ullong_t: %d\n", sizeof(ullong_t));

  if (is_svm_capable()) {
    vmm_cpu_type = VMM_SVM_CPU;
    PrintDebug("Machine is SVM Capable\n");
    Init_SVM();
  } else if (is_vmx_capable()) {
    vmm_cpu_type = VMM_VMX_CPU;
    PrintDebug("Machine is VMX Capable\n");
    Init_VMX();
  } else {
    PrintDebug("CPU has no virtualization Extensions\n");
  }
}
