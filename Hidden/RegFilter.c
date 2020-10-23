#include "RegFilter.h"
#include "Driver.h"

#include <Ntstrsafe.h>

#define FILTER_ALLOC_TAG 'FRlF'

BOOLEAN g_regFilterInited = FALSE;
WCHAR g_excludeRegKey[BUFSIZE] = { 0 };
UNICODE_STRING us_excludeRegKey;
LARGE_INTEGER g_regCookie = { 0 };

BOOLEAN GetNameFromEnumKeyPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID infoBuffer, PUNICODE_STRING keyName)
{
	switch (infoClass)
	{
	case KeyBasicInformation:
		{
			PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	case KeyNameInformation:
		{
			PKEY_NAME_INFORMATION keyInfo = (PKEY_NAME_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

NTSTATUS CheckRegKeyValueName(PUNICODE_STRING Key, PUNICODE_STRING Name)
{
	UNICODE_STRING fullName;
	NTSTATUS status = STATUS_SUCCESS;

	fullName.Length = 0;
	fullName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	fullName.Buffer = ExAllocatePoolWithTag(NonPagedPool, fullName.MaximumLength, FILTER_ALLOC_TAG);
	if (!fullName.Buffer)
	{
		_InfoPrint("Error, memory allocation failed\n");
		return STATUS_INTERNAL_ERROR;
	}

	RtlUnicodeStringCopy(&fullName, Key);
	RtlAppendUnicodeToString(&fullName, L"\\");
	RtlUnicodeStringCat(&fullName, Name);

	if(RtlCompareUnicodeString(&fullName, &us_excludeRegKey, TRUE) != 0)
	{
		status = STATUS_INTERNAL_ERROR;
	}

	ExFreePoolWithTag(fullName.Buffer, FILTER_ALLOC_TAG);
	return status;
}

NTSTATUS RegPostEnumKey(PVOID context, PREG_POST_OPERATION_INFORMATION info)
{
	PREG_ENUMERATE_KEY_INFORMATION preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING keyName;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(context);

	if (!NT_SUCCESS(info->Status))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		_InfoPrint("Error, registry name query failed with code:%08x", status);
		return STATUS_SUCCESS;
	}

	preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;

	if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName))
		return STATUS_SUCCESS;

	status = CheckRegKeyValueName((PUNICODE_STRING)regPath, &keyName);
	if (NT_SUCCESS(status))
	{
		_InfoPrint("Registry key is going to be hidden in: %wZ", regPath);

		HANDLE Key;
		ULONG resLen, i;
		BOOLEAN infinite = TRUE;
		PVOID tempBuffer;

		status = ObOpenObjectByPointer(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, &Key);
		if (!NT_SUCCESS(status))
		{
			_InfoPrint("Error, ObOpenObjectByPointer() failed with code:%08x", status);
			return STATUS_SUCCESS;
		}

		tempBuffer = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, FILTER_ALLOC_TAG);
		if (tempBuffer)
		{
			for (i = 0; infinite; i++)
			{
				status = ZwEnumerateKey(Key, preInfo->Index + 1, preInfo->KeyInformationClass, tempBuffer, preInfo->Length, &resLen);
				if (!NT_SUCCESS(status))
					break;

				if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, tempBuffer, &keyName))
					break;

				status = CheckRegKeyValueName((PUNICODE_STRING)regPath, &keyName);
				if (!NT_SUCCESS(status))
				{
					*preInfo->ResultLength = resLen;
					__try
					{
						RtlCopyMemory(preInfo->KeyInformation, tempBuffer, resLen);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						_InfoPrint("Warning, can't copy new key information");
					}

					break;
				}
			}

			ExFreePoolWithTag(tempBuffer, FILTER_ALLOC_TAG);
		}
		else
		{
			status = STATUS_SUCCESS;
		}

		info->ReturnStatus = status;

		ZwClose(Key);
	}

	return STATUS_SUCCESS;
}

_Function_class_(EX_CALLBACK_FUNCTION)
NTSTATUS RegistryFilterCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsDriverEnabled())
		return status;

	if (notifyClass == RegNtPostEnumerateKey)
		status = RegPostEnumKey(CallbackContext, (PREG_POST_OPERATION_INFORMATION)Argument2);

	return status;
}

NTSTATUS InitializeRegistryFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	UNICODE_STRING altitude;

	RtlInitUnicodeString(&altitude, L"320000");

	status = CmRegisterCallbackEx(&RegistryFilterCallback, &altitude, DriverObject, NULL, &g_regCookie, NULL);
	if (!NT_SUCCESS(status))
	{
		_InfoPrint("Error, registry filter registration failed with code:%08x", status);
		return status;
	}

	g_regFilterInited = TRUE;
	_InfoPrint("Initialization is completed");
	return status;
}

NTSTATUS DestroyRegistryFilter()
{
	NTSTATUS status;

	if (!g_regFilterInited)
		return STATUS_NOT_FOUND;

	status = CmUnRegisterCallback(g_regCookie);
	if (!NT_SUCCESS(status))
		_InfoPrint("Warning, registry filter unregistration failed with code:%08x", status);

	g_regFilterInited = FALSE;
	_InfoPrint("Deinitialization is completed (Reg)");
	return status;
}
