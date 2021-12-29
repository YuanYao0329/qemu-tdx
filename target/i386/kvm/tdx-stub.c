#include "qemu/osdep.h"
#include "qemu-common.h"

#include "tdx.h"

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    return -EINVAL;
}

int tdx_pre_create_vcpu(CPUState *cpu)
{
    return -EINVAL;
}

void tdx_set_bfv_cfv_ptr(void *bfv_ptr, void *cfv_ptr, bool split_tdvf)
{
}
