#ifndef HW_I386_TD_HOB_H
#define HW_I386_TD_HOB_H

#include "hw/i386/tdvf.h"
#include "hw/i386/uefi.h"
#include "target/i386/kvm/tdx.h"

void tdvf_hob_create(TdxGuest *tdx, TdxFirmwareEntry *hob_entry);

#define EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE     \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_ENCRYPTED |         \
     EFI_RESOURCE_ATTRIBUTE_TESTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED  \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_UNACCEPTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_MMIO        \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT     |       \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE)

#endif
