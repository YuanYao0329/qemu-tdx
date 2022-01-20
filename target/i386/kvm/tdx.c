/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"

#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "kvm_i386.h"
#include "tdx.h"

#define TDX_TD_ATTRIBUTES_DEBUG     BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_PERFMON    BIT_ULL(63)

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

static TdxGuest *tdx_guest;

bool is_tdx_vm(void)
{
    return !!tdx_guest;
}

TdxGuest *get_tdx_guest(void)
{
    if (!tdx_guest) {
        error_report("tdx_guest not initialized!\n");
        exit(1);
    }

    return tdx_guest;
}

enum tdx_ioctl_level{
    TDX_PLATFORM_IOCTL,
    TDX_VM_IOCTL,
    TDX_VCPU_IOCTL,
};

static int __tdx_ioctl(void *state, enum tdx_ioctl_level level, int cmd_id,
                        __u32 metadata, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int r;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = cmd_id;
    tdx_cmd.metadata = metadata;
    tdx_cmd.data = (__u64)(unsigned long)data;

    switch (level) {
    case TDX_PLATFORM_IOCTL:
        r = kvm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VM_IOCTL:
        r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VCPU_IOCTL:
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    default:
        error_report("Invalid tdx_ioctl_level %d", level);
        exit(1);
    }

    return r;
}

#define tdx_platform_ioctl(cmd_id, metadata, data) \
        __tdx_ioctl(NULL, TDX_PLATFORM_IOCTL, cmd_id, metadata, data)

#define tdx_vm_ioctl(cmd_id, metadata, data) \
        __tdx_ioctl(NULL, TDX_VM_IOCTL, cmd_id, metadata, data)

#define tdx_vcpu_ioctl(cpu, cmd_id, metadata, data) \
        __tdx_ioctl(cpu, TDX_VCPU_IOCTL, cmd_id, metadata, data)

static struct kvm_tdx_capabilities *tdx_caps;

static void get_tdx_capabilities(void)
{
    struct kvm_tdx_capabilities *caps;
    int max_ent = 1;
    int r, size;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
               max_ent * sizeof(struct kvm_tdx_cpuid_config);
        caps = g_malloc0(size);
        caps->nr_cpuid_configs = max_ent;

        r = tdx_platform_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            g_free(caps);
            max_ent *= 2;
        } else if (r < 0) {
            error_report("KVM_TDX_CAPABILITIES failed: %s\n", strerror(-r));
            exit(1);
        }
    }
    while (r == -E2BIG);

    tdx_caps = caps;
}

static int tdx_validate_attributes(TdxGuest *tdx)
{
    if (((tdx->attributes & tdx_caps->attrs_fixed0) | tdx_caps->attrs_fixed1) !=
        tdx->attributes) {
            error_report("Invalid attributes 0x%lx for TDX VM (fixed0 0x%llx, fixed1 0x%llx)",
                          tdx->attributes, tdx_caps->attrs_fixed0, tdx_caps->attrs_fixed1);
            return -EINVAL;
    }

    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_report("Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -EINVAL;
    }

    return 0;
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    void *base_ram_ptr = memory_region_get_ram_ptr(ms->ram);
    TdxFirmwareEntry *entry;

    for_each_tdx_fw_entry(tdx_guest, entry) {
        if (entry->type == TDVF_SECTION_TYPE_BFV) {
            if (!tdx_guest->split_tdvf) {
                entry->mem_ptr = tdx_guest->bfv_ptr + entry->data_offset;
            } else {
                entry->mem_ptr = tdx_guest->bfv_ptr;
            }
        } else if( entry->type == TDVF_SECTION_TYPE_CFV) {
            if (!tdx_guest->split_tdvf) {
                entry->mem_ptr = tdx_guest->bfv_ptr;
            } else {
                entry->mem_ptr = tdx_guest->cfv_ptr;
            }
        } else {
            entry->mem_ptr = base_ram_ptr + entry->address;
        }
    }
}

static Notifier tdx_machine_done_late_notify = {
    .notify = tdx_finalize_vm,
};

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    int r;
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    if (!tdx) {
        return -EINVAL;
    }

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    r = tdx_validate_attributes(tdx);
    if (r) {
        return r;
    }

    qemu_add_machine_init_done_notifier(&tdx_machine_done_late_notify);

    return 0;
}

void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret)
{
    if (!tdx_guest) {
        return;
    }

    switch (function) {
    case 1:
        if (reg == R_ECX) {
            *ret &= ~CPUID_EXT_VMX;
        }
        break;
    case 0xd:
        if (index == 0) {
            if (reg == R_EAX) {
                *ret &= (uint32_t)tdx_caps->xfam_fixed0 & XCR0_MASK;
                *ret |= (uint32_t)tdx_caps->xfam_fixed1 & XCR0_MASK;
            } else if (reg == R_EDX) {
                *ret &= (tdx_caps->xfam_fixed0 & XCR0_MASK) >> 32;
                *ret |= (tdx_caps->xfam_fixed1 & XCR0_MASK) >> 32;
            }
        } else if (index == 1) {
            /* TODO: Adjust XSS when it's supported. */
        }
        break;
    case KVM_CPUID_FEATURES:
        if (reg == R_EAX) {
            *ret &= ~((1ULL << KVM_FEATURE_CLOCKSOURCE) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE2) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_VMEXIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_INT));
        }
        break;
    default:
        /* TODO: Use tdx_caps to adjust CPUID leafs. */
        break;
    }
}

int tdx_pre_create_vcpu(CPUState *cpu)
{
    struct {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
    } cpuid_data;

    /*
     * The kernel defines these structs with padding fields so there
     * should be no extra padding in our cpuid_data struct.
     */
    QEMU_BUILD_BUG_ON(sizeof(cpuid_data) !=
                      sizeof(struct kvm_cpuid2) +
                      sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct kvm_tdx_init_vm init_vm;
    int r = 0;

    /* TODO: Use tdx_caps to validate the config. */
    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        error_report("TDX VM must support XSAVE features");
        exit(1);
    }

    if (env->tsc_khz && (env->tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ)) {
        error_report("Invalid TSC %ld KHz, must specify cpu_frequency between [%d, %d] kHz\n",
                      env->tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ,
                      TDX_MAX_TSC_FREQUENCY_KHZ);
        exit(1);
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_report("Invalid TSC %ld KHz, it must be multiple of 25MHz\n", env->tsc_khz);
        exit(1);
    }

    qemu_mutex_lock(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        goto out;
    }
    tdx_guest->initialized = true;

    memset(&cpuid_data, 0, sizeof(cpuid_data));

    cpuid_data.cpuid.nent = kvm_x86_arch_cpuid(env, cpuid_data.entries, 0);

    init_vm.max_vcpus = ms->smp.cpus;
    init_vm.tsc_khz = env->tsc_khz;
    init_vm.attributes = tdx_guest->attributes;
    init_vm.attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;

    init_vm.cpuid = (__u64)(&cpuid_data);
    r = tdx_vm_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);
    if (r < 0) {
        error_report("KVM_TDX_INIT_VM failed %s", strerror(-r));
    }

out:
    qemu_mutex_unlock(&tdx_guest->lock);
    return r;
}

void tdx_set_bfv_cfv_ptr(void *bfv_ptr, void *cfv_ptr, bool split_tdvf)
{
    tdx_guest->bfv_ptr = bfv_ptr;
    tdx_guest->cfv_ptr = cfv_ptr;
    tdx_guest->split_tdvf = split_tdvf;
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   CONFIDENTIAL_GUEST_SUPPORT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    qemu_mutex_init(&tdx->lock);

    tdx->attributes = 0;
    object_property_add_uint64_ptr(obj, "attributes", &tdx->attributes,
                                   OBJ_PROP_FLAG_READ | OBJ_PROP_FLAG_WRITE);
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
