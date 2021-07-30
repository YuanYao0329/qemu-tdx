#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/tdx.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-target.h"

#ifndef CONFIG_USER_ONLY
bool kvm_has_tdx(KVMState *s)
{
        return false;
}

int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory)
{
    return -ENOSYS;
}
#endif

bool kvm_tdx_enabled(void)
{
    return false;
}

void tdx_pre_create_vcpu(CPUState *cpu)
{
}

void tdx_post_init_vcpu(CPUState *cpu)
{
}

struct TDXInfo *tdx_get_info(void)
{
    return NULL;
}

void tdx_update_xfam_features(CPUState *cpu)
{
}

/* QMP */
struct TDXCapability *tdx_get_capabilities(void)
{
    return NULL;
}

TDXInfo *qmp_query_tdx(Error **errp)
{
    error_setg(errp, "TDX is not available in this QEMU.");
    return NULL;
}

TDXCapability *qmp_query_tdx_capabilities(Error **errp)
{
    error_setg(errp, "TDX is not available in this QEMU.");
    return NULL;
}
