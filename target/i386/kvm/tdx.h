#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

#include "exec/confidential-guest-support.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)

typedef struct TdxGuestClass {
    ConfidentialGuestSupportClass parent_class;
} TdxGuestClass;

typedef struct TdxFirmwareEntry {
    uint32_t data_offset;
    uint32_t data_len;
    uint64_t address;
    uint64_t size;
    uint32_t type;
    uint32_t attributes;

    void *mem_ptr;
} TdxFirmwareEntry;

typedef struct TdxRamEntry {
    uint64_t address;
    uint64_t length;
    uint32_t type;
} TdxRamEntry;

typedef struct TdxGuest {
    ConfidentialGuestSupport parent_obj;

    QemuMutex lock;

    bool initialized;
    uint64_t attributes;    /* TD attributes */

    uint32_t nr_fw_entries;
    TdxFirmwareEntry *fw_entries;

    uint32_t nr_ram_entries;
    TdxRamEntry *ram_entries;

    bool split_tdvf;
    void *bfv_ptr;
    void *cfv_ptr;
} TdxGuest;

#define for_each_tdx_fw_entry(tdx, e)    \
    for (e = (tdx)->fw_entries; e != (tdx)->fw_entries + (tdx)->nr_fw_entries; e++)

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
TdxGuest *get_tdx_guest(void);
#else
#define is_tdx_vm() 0
inline TdxGuest *get_tdx_guest(void) {return NULL;}
#endif /* CONFIG_TDX */

int tdx_kvm_init(MachineState *ms, Error **errp);
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret);
int tdx_pre_create_vcpu(CPUState *cpu);
int tdx_post_init_vcpu(CPUState *cpu);
void tdx_set_bfv_cfv_ptr(void *bfv_ptr, void *cfv_ptr, bool split_tdvf);

#endif /* QEMU_I386_TDX_H */
