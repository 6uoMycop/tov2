#pragma once

#include <Ntddk.h>

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyFSMiniFilter();

NTSTATUS AddHiddenFile(PUNICODE_STRING FilePath, PULONGLONG ObjId);
NTSTATUS RemoveHiddenFile(ULONGLONG ObjId);
NTSTATUS RemoveAllHiddenFiles();
