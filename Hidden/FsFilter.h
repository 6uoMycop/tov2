#pragma once

#include <Ntddk.h>

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyFSMiniFilter();
