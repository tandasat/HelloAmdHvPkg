#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Pi/PiMultiPhase.h>
#include <Protocol/MpService.h>

//
// Single memory log entry.
//
typedef struct _MEMORY_LOG_ENTRY
{
    UINT32 GlobalIndex;
    CHAR8 Message[60];
} MEMORY_LOG_ENTRY;

//
// 4KB memory log entry buffer allocated for each processor.
//
typedef struct _MEMORY_LOGS
{
    volatile UINT32 NextPosition;
    UINT8 Reserved1[12];
    MEMORY_LOG_ENTRY Entries[(SIZE_4KB - 16) / sizeof(MEMORY_LOG_ENTRY)];
    UINT8 Reserved2[48];
} MEMORY_LOGS;
STATIC_ASSERT(sizeof(MEMORY_LOGS) == SIZE_4KB, "Must be 4KB aligned");

//
// Log related globals.
//
STATIC MEMORY_LOGS g_Logs;
STATIC EFI_GUID g_LogGuid =
{
    0x212d9932,
    0x0138,
    0x4104,
    { 0xb0, 0x41, 0xfb, 0x74, 0xd0, 0xe8, 0xa6, 0x75, },
};

STATIC
EFI_STATUS
DumpLogs (
    IN UINT32 ProcessorNumber
    )
{
    EFI_STATUS status;
    CHAR16 variableName[16];
    UINTN dataSize;

    UnicodeSPrint(variableName, sizeof(variableName), L"Log#%d", ProcessorNumber);

    Print(L"Reading %s\n", variableName);
    dataSize = sizeof(g_Logs);
    status = gRT->GetVariable(variableName, &g_LogGuid, NULL, &dataSize, &g_Logs);
    if (EFI_ERROR(status))
    {
        Print(L"Reading %s failed : %r\n", variableName, status);
        goto Exit;
    }

    for (UINT32 i = 0; i < ARRAY_SIZE(g_Logs.Entries); ++i)
    {
        if (g_Logs.Entries[i].Message[0] != CHAR_NULL)
        {
            Print(L"#%4d: %a", g_Logs.Entries[i].GlobalIndex, g_Logs.Entries[i].Message);
        }
    }

Exit:
    return status;
}

EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    EFI_STATUS status;
    EFI_MP_SERVICES_PROTOCOL* mpServices;
    UINTN numberOfProcessors;
    UINTN numberOfEnabledProcessors;

    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID**)&mpServices);
    ASSERT_EFI_ERROR(status);

    status = mpServices->GetNumberOfProcessors(mpServices,
                                               &numberOfProcessors,
                                               &numberOfEnabledProcessors);
    ASSERT_EFI_ERROR(status);

    for (UINT32 i = 0; i < numberOfEnabledProcessors; i++)
    {
        DumpLogs(i);
    }

    return EFI_SUCCESS;
}
