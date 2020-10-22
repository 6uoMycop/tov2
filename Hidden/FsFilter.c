// =========================================================================================
//       Filesystem Minifilter
// =========================================================================================

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "FsFilter.h"
#include "Helper.h"
#include "Driver.h"

#define FSFILTER_ALLOC_TAG 'DHlF'

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);

const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_DIRECTORY_CONTROL, 0, FltDirCtrlPreOperation, FltDirCtrlPostOperation },
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION), //  Size
	FLT_REGISTRATION_VERSION, //  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,                        //  Flags
	Contexts,                 //  Context
	Callbacks,                //  Operation callbacks
	/*FilterUnload*/NULL,     //  MiniFilterUnload
	FilterSetup,              //  InstanceSetup
	NULL,                     //  InstanceQueryTeardown
	NULL,                     //  InstanceTeardownStart
	NULL,                     //  InstanceTeardownComplete
	NULL,                     //  GenerateFileName
	NULL,                     //  GenerateDestinationFileName
	NULL                      //  NormalizeNameComponent
};

BOOLEAN g_fsMonitorInited = FALSE;
PFLT_FILTER gFilterHandle = NULL;

WCHAR g_excludeFile[BUFSIZE] = { 0 };
UNICODE_STRING us_excludeFile;

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	_InfoPrint("Attach to a new device (flags:%x, device:%d, fs:%d)", (ULONG)Flags, (ULONG)VolumeDeviceType, (ULONG)VolumeFilesystemType);

	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	//_InfoPrint("FltDirCtrlPreOperation: %wZ", &Data->Iopb->TargetFileObject->FileName);

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdFullDirectoryInformation:
	case FileIdBothDirectoryInformation:
	case FileBothDirectoryInformation:
	case FileDirectoryInformation:
	case FileFullDirectoryInformation:
	case FileNamesInformation:
		break;
	default:
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_PARAMETERS params = &Data->Iopb->Parameters;
	PFLT_FILE_NAME_INFORMATION fltName;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(Data->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
	if (!NT_SUCCESS(status))
	{
		_InfoPrint("FltGetFileNameInformation() failed with code:%08x", status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	__try
	{
		status = STATUS_SUCCESS;

		switch (params->DirectoryControl.QueryDirectory.FileInformationClass)
		{
		case FileIdBothDirectoryInformation:
			status = CleanFileIdBothDirectoryInformation((PFILE_ID_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		}

		Data->IoStatus.Status = status;
	}
	__finally
	{
		FltReleaseFileNameInformation(fltName);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_ID_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName, fullName;
	UINT32 offset, moveLength;
	BOOLEAN matched = FALSE, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	fullName.Length = 0;
	fullName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	fullName.Buffer = ExAllocatePoolWithTag(NonPagedPool, fullName.MaximumLength, FSFILTER_ALLOC_TAG);
	if (!fullName.Buffer)
	{
		_InfoPrint("Error, memory allocation failed with code:%08x\n", status);
		return FALSE;
	}

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		RtlUnicodeStringCopy(&fullName, &fltName->Name);
		RtlAppendUnicodeToString(&fullName, L"\\");
		RtlUnicodeStringCat(&fullName, &fileName);

		if (!(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			matched = (RtlCompareUnicodeString(&fullName, &us_excludeFile, TRUE) == 0) ? TRUE : FALSE;
			_InfoPrint("%ws: %wZ", matched ? L"TRUE" : L"FALSE", &fullName);
		}

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			if (retn)
			{
				ExFreePoolWithTag(fullName.Buffer, FSFILTER_ALLOC_TAG);
				return status;
			}

			info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	ExFreePoolWithTag(fullName.Buffer, FSFILTER_ALLOC_TAG);
	return status;
}

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;

	// Filesystem mini-filter initialization

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			_InfoPrint("Error, can't start filtering, code:%08x", status);
			FltUnregisterFilter(gFilterHandle);
		}
	}
	else
	{
		_InfoPrint("Error, can't register filter, code:%08x", status);
	}

	if (!NT_SUCCESS(status))
		return status;

	g_fsMonitorInited = TRUE;

	_InfoPrint("Initialization is completed");
	return status;
}

NTSTATUS DestroyFSMiniFilter()
{
	if (!g_fsMonitorInited)
		return STATUS_NOT_FOUND;

	FltUnregisterFilter(gFilterHandle);
	gFilterHandle = NULL;

	g_fsMonitorInited = FALSE;

	_InfoPrint("Deinitialization is completed (Fs)");
	return STATUS_SUCCESS;
}
