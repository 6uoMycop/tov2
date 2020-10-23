#pragma once

#include <Ntddk.h>

#define BUFSIZE 256
#define DRIVER_NAME             L"Fltr"

#define _InfoPrint(str, ...)        \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
               DPFLTR_ERROR_LEVEL,  \
               "%S: "##str"\n",     \
               DRIVER_NAME,         \
               __VA_ARGS__)

VOID EnableDisableDriver(BOOLEAN enabled);
BOOLEAN IsDriverEnabled();
