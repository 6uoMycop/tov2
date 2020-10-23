#pragma once

#include <Ntifs.h>

NTSTATUS InitializeRegistryFilter(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyRegistryFilter();
