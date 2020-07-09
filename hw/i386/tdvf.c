/*
 * SPDX-License-Identifier: GPL-2.0-or-later

 * Copyright (c) 2020 Intel Corporation
 * Author: Isaku Yamahata <isaku.yamahata at gmail.com>
 *                        <isaku.yamahata at intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "sysemu/kvm.h"

#include "hw/i386/pc.h"
#include "hw/i386/tdvf.h"
#include "kvm/tdx.h"


#define TDX_METADATA_GUID "e47a6535-984a-4798-865e-4685a7bf8ec2"
struct tdx_metadata_offset {
    uint32_t offset;
};

static TdvfMetadata *tdvf_get_metadata(void *flash_ptr, int size)
{
    TdvfMetadata *metadata;
    uint32_t offset = 0;
    uint8_t *data;

    if ((uint32_t) size != size) {
        return NULL;
    }

    if (pc_system_ovmf_table_find(TDX_METADATA_GUID, &data, NULL)) {
        offset = size - le32_to_cpu(((struct tdx_metadata_offset *)data)->offset);

        if (offset + sizeof(*metadata) > size) {
            return NULL;
        }
    } else {
        warn_report("Cannot find TDX_METADATA_GUID\n");
        return NULL;
    }

    metadata = flash_ptr + offset;

    /* Finally, verify the signature to determine if this is a TDVF image. */
   if (metadata->Signature != TDVF_SIGNATURE_LE32) {
       warn_report("Invalid TDVF signature in metadata!\n");
       return NULL;
   }

    /* Sanity check that the TDVF doesn't overlap its own metadata. */
    metadata->Length = le32_to_cpu(metadata->Length);
    if (offset + metadata->Length > size) {
        return NULL;
    }

    /* Only version 1 is supported/defined. */
    metadata->Version = le32_to_cpu(metadata->Version);
    if (metadata->Version != 1) {
        return NULL;
    }

    printf("TDVF Metadata, Length 0x%x, Version 0x%x, NumEntries 0x%x\n",
            metadata->Length, metadata->Version, metadata->NumberOfSectionEntries);

    return metadata;
}

static void tdvf_parse_section_entry(TdxFirmwareEntry *entry,
                                     const TdvfSectionEntry *src)
{
    entry->data_offset = le32_to_cpu(src->DataOffset);
    entry->data_len = le32_to_cpu(src->RawDataSize);
    entry->address = le64_to_cpu(src->MemoryAddress);
    entry->size = le64_to_cpu(src->MemoryDataSize);
    entry->type = le32_to_cpu(src->Type);
    entry->attributes = le32_to_cpu(src->Attributes);

    printf("type %d, attributes 0x%x, data_offset 0x%x, data_len 0x%x, address 0x%lx, size 0x%lx\n",
            entry->type, entry->attributes, entry->data_offset, entry->data_len, entry->address, entry->size);
    /* sanity check */
    if (entry->size < entry->data_len) {
        error_report("broken metadata RawDataSize 0x%x MemoryDataSize 0x%lx",
                     entry->data_len, entry->size);
        exit(1);
    }
    if (!QEMU_IS_ALIGNED(entry->address, TARGET_PAGE_SIZE)) {
        error_report("MemoryAddress 0x%lx not page aligned", entry->address);
        exit(1);
    }
    if (!QEMU_IS_ALIGNED(entry->size, TARGET_PAGE_SIZE)) {
        error_report("MemoryDataSize 0x%lx not page aligned", entry->size);
        exit(1);
    }
    if (entry->type == TDVF_SECTION_TYPE_TD_HOB ||
        entry->type == TDVF_SECTION_TYPE_TEMP_MEM ||
        entry->type == TDVF_SECTION_TYPE_PERM_MEM) {
        if (entry->data_len != 0) {
            error_report("%d section with RawDataSize 0x%x != 0",
                         entry->type, entry->data_len);
            exit(1);
        }
    }
    if (entry->type == TDVF_SECTION_TYPE_BFV ||
        entry->type == TDVF_SECTION_TYPE_CFV) {
        if (entry->data_len == 0) {
            error_report("%d section with RawDataSize == 0", entry->type);
            exit(1);
        }
    }
}

int tdvf_parse_metadata(void *flash_ptr, int size)
{
    TdvfSectionEntry *sections;
    TdvfMetadata *metadata;
    TdxGuest *tdx;
    uint32_t len, i;
    ssize_t entries_size;

    tdx = get_tdx_guest();
    if (!tdx) {
        return -1;
    }

    metadata = tdvf_get_metadata(flash_ptr, size);
    if (!metadata) {
        return -1;
    }

    //load and parse metadata entries
    tdx->nr_fw_entries = le32_to_cpu(metadata->NumberOfSectionEntries);
    if (tdx->nr_fw_entries < 2) {
        error_report("Invalid number of fw entries (%u) in TDVF", tdx->nr_fw_entries);
        exit(1);
    }

    len = le32_to_cpu(metadata->Length);
    entries_size = tdx->nr_fw_entries * sizeof(TdvfSectionEntry);
    if (len != sizeof(*metadata) + entries_size) {
        error_report("TDVF metadata len (0x%x) mismatch, expected (0x%x)",
                     len, (uint32_t)(sizeof(*metadata) + entries_size));
        exit(1);
    }

    tdx->fw_entries = g_new(TdxFirmwareEntry, tdx->nr_fw_entries);
    sections = g_new(TdvfSectionEntry, tdx->nr_fw_entries);

    if (!memcpy(sections, (void *)metadata + sizeof(*metadata), entries_size))  {
        error_report("Failed to read TDVF section entries");
        exit(1);
    }

    for (i = 0; i < tdx->nr_fw_entries; i++) {
        tdvf_parse_section_entry(&tdx->fw_entries[i], &sections[i]);
    }
    g_free(sections);

    return 0;
}
