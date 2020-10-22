#pragma once

#include <Ntifs.h>

NTSTATUS InitializeRegistryFilter(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyRegistryFilter();

NTSTATUS AddHiddenRegKey(PUNICODE_STRING KeyPath, PULONGLONG ObjId);
