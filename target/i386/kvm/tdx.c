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

#include "hw/i386/x86.h"
#include "tdx.h"

#define TDX_TD_ATTRIBUTES_DEBUG     BIT_ULL(0)

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    if (!tdx) {
        return -EINVAL;
    }

    return 0;
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
