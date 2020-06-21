/**
 * @file Setup.c
 *
 * @brief Implements the entry point of the module and logic to start the hypervisor.
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include "HelloAmdHv.h"

/**
 * @brief The array of the default host exception handlers.
 */
VOID
AsmDefaultExceptionHandlers (
    VOID
    );

/**
 * @brief Returns the return address from this function.
 */
UINTN
AsmReadInstructionPointer (
    VOID
    );

/**
 * @brief Returns the current value of RSP.
 */
UINTN
AsmReadStackPointer (
    VOID
    );

/**
 * @brief Enters the loop that executes the guest and handles #VMEXIT.
 */
VOID
AsmLaunchVm (
    IN VOID* HostRsp
    );

//
// The segment attributes required for VMCB.
//
typedef union _SEGMENT_ATTRIBUTE
{
    struct
    {
        UINT16 Type : 4;        // [0:3]
        UINT16 System : 1;      // [4]
        UINT16 Dpl : 2;         // [5:6]
        UINT16 Present : 1;     // [7]
        UINT16 Avl : 1;         // [8]
        UINT16 LongMode : 1;    // [9]
        UINT16 DefaultBit : 1;  // [10]
        UINT16 Granularity : 1; // [11]
        UINT16 Reserved1 : 4;   // [12:15]
    } Bits;
    UINT16 Uint16;
} SEGMENT_ATTRIBUTE;
STATIC_ASSERT(sizeof(SEGMENT_ATTRIBUTE) == 2, "Unexpected size");

//
// Context that is needed to feed to VMCB for the guest.
//
typedef struct _GUEST_CONTEXT
{
    IA32_DESCRIPTOR Gdtr;
    IA32_DESCRIPTOR Idtr;

    UINT16 SegCs;
    UINT16 SegDs;
    UINT16 SegEs;
    UINT16 SegSs;

    UINT64 Efer;
    UINT64 GPat;
    UINT64 Cr0;
    UINT64 Cr2;
    UINT64 Cr3;
    UINT64 Cr4;
    UINT64 Rflags;
    UINT64 Rsp;
    UINT64 Rip;
} GUEST_CONTEXT;

//
// Fills in the GUEST_CONTEXT. This must be a macro (ie, not a function) so that
// AsmReadStackPointer does not capture the address whose contents can be
// overwritten in the later step.
//
#define CAPTURE_CONTEXT(ContextRecord)                      \
    AsmReadGdtr(&(ContextRecord)->Gdtr);                    \
    AsmReadIdtr(&(ContextRecord)->Idtr);                    \
    (ContextRecord)->SegCs = AsmReadCs();                   \
    (ContextRecord)->SegDs = AsmReadDs();                   \
    (ContextRecord)->SegEs = AsmReadEs();                   \
    (ContextRecord)->SegSs = AsmReadSs();                   \
    (ContextRecord)->Efer = AsmReadMsr64(MSR_IA32_EFER);    \
    (ContextRecord)->GPat = AsmReadMsr64(MSR_IA32_PAT);     \
    (ContextRecord)->Cr0 = AsmReadCr0();                    \
    (ContextRecord)->Cr2 = AsmReadCr2();                    \
    (ContextRecord)->Cr3 = AsmReadCr3();                    \
    (ContextRecord)->Cr4 = AsmReadCr4();                    \
    (ContextRecord)->Rflags = AsmReadEflags();              \
    (ContextRecord)->Rsp = AsmReadStackPointer();           \
    (ContextRecord)->Rip = AsmReadInstructionPointer()

//
// The remaining count to stop local APIC access interception.
//
volatile UINT32 g_RemainingSipiCount;

//
// The physical address of the ResetSystem runtime service.
//
EFI_RESET_SYSTEM g_ResetSystemPhys;

//
// Log buffer to use for assertion.
//
MEMORY_LOGS* g_GlobalLogBuffer;

//
// MP procotol.
//
STATIC EFI_MP_SERVICES_PROTOCOL* g_MpServices;

/**
 * @brief Initializes globals used by the host.
 */
STATIC
VOID
InitializeHostDebugFacility (
    IN ROOT_CONTEXT* Context
    )
{
    ASSERT(g_ResetSystemPhys == NULL);
    g_ResetSystemPhys = gRT->ResetSystem;

    g_GlobalLogBuffer = &Context->Cpus[0].Logs;
}

/**
 * @brief Returns the current processor number. 0 for BSP.
 */
STATIC
UINT32
GetCurrentProcessorNumber (
    VOID
    )
{
    EFI_STATUS status;
    UINTN processorNumber;

    status = g_MpServices->WhoAmI(g_MpServices, &processorNumber);
    ASSERT_EFI_ERROR(status);

    return (UINT32)processorNumber;
}

/**
 * @brief Returns the number of active processors.
 */
STATIC
UINT32
GetActiveProcessorCount (
    VOID
    )
{
    EFI_STATUS status;
    UINTN numberOfProcessors;
    UINTN numberOfEnabledProcessors;

    status = g_MpServices->GetNumberOfProcessors(g_MpServices,
                                                 &numberOfProcessors,
                                                 &numberOfEnabledProcessors);
    ASSERT_EFI_ERROR(status);

    return (UINT32)numberOfEnabledProcessors;
}

/**
 * @brief Executes the function on all processors one by one.
 */
STATIC
VOID
RunOnAllProcessors (
    IN EFI_AP_PROCEDURE Callback,
    IN VOID* Context
    )
{
    EFI_STATUS status;

    Callback(Context);
    if (GetActiveProcessorCount() == 1)
    {
        return;
    }

    //
    // Execute the callback one by one. Multi-threading make logs look unreadable
    // and can even crashes the system because of some of logging function calls.
    //
    status = g_MpServices->StartupAllAPs(g_MpServices,
                                         Callback,
                                         TRUE,
                                         NULL,
                                         0,
                                         Context,
                                         NULL);
    ASSERT_EFI_ERROR(status);
}

/**
 * @brief Switches the current execution environment to the given environment.
 */
STATIC
VOID
SwitchToHostContext (
    IN CONST SHARED_HOST_DATA* SharedHostData,
    IN CONST HOST_DATA* HostData
    )
{
    AsmWriteCr3(SharedHostData->Cr3);
    AsmWriteIdtr(&SharedHostData->Idtr);
    AsmWriteGdtr(&HostData->Gdtr);
}

/**
 * @brief Initializes the per-processor host environment data structures.
 */
STATIC
VOID
InitializeHostData (
    OUT HOST_DATA* HostData,
    IN CONST SHARED_HOST_DATA* SharedHostData
    )
{
    IA32_DESCRIPTOR gdtr;

    ZeroMem(HostData, sizeof(*HostData));

    //
    // Read the current GDTR and make sure buffer to have a copy of this is large
    // enough to clone the current GDT.
    //
    AsmReadGdtr(&gdtr);
    ASSERT(sizeof(HostData->Gdt) >= gdtr.Limit + 1);

    //
    // Initialize the per processor host data structures.
    //
    HostData->Shared = SharedHostData;
    CopyMem(HostData->Gdt, (VOID*)gdtr.Base, gdtr.Limit + 1);
    HostData->Gdtr.Base = (UINT64)&HostData->Gdt[0];
    HostData->Gdtr.Limit = gdtr.Limit;
}

/**
 * @brief Returns the access right value required for VMCB for the specified segment.
 */
#define RPL_MASK        3
STATIC
UINT16
GetSegmentAccessRight (
    IN UINT16 SegmentSelector,
    IN UINT64 GdtBase
    )
{
    IA32_SEGMENT_DESCRIPTOR* descriptor;
    SEGMENT_ATTRIBUTE attribute;

    //
    // Get a segment descriptor corresponds to the specified segment selector.
    //
    descriptor = (IA32_SEGMENT_DESCRIPTOR*)(
                                        GdtBase + (SegmentSelector & ~RPL_MASK));

    //
    // Extract all attribute fields in the segment descriptor to a structure
    // that describes only attributes (as opposed to the segment descriptor
    // consists of multiple other fields).
    //
    attribute.Bits.Type = (UINT16)descriptor->Bits.Type;
    attribute.Bits.System = (UINT16)descriptor->Bits.S;
    attribute.Bits.Dpl = (UINT16)descriptor->Bits.DPL;
    attribute.Bits.Present = (UINT16)descriptor->Bits.P;
    attribute.Bits.Avl = (UINT16)descriptor->Bits.AVL;
    attribute.Bits.LongMode = (UINT16)descriptor->Bits.L;
    attribute.Bits.DefaultBit = (UINT16)descriptor->Bits.DB;
    attribute.Bits.Granularity = (UINT16)descriptor->Bits.G;
    attribute.Bits.Reserved1 = 0;

    return attribute.Uint16;
}

/**
 * @brief Prepares the system for virtualization.
 *
 * @details This function first fills in the gust VMCS with the provided guest
 *      context object, populates data to pass to the host in its stack,
 *      initializes other this-project defined state fields, register local APIC
 *      access intercept, then swiches the x64 data structures to ones prepared
 *      for the host.
 */
STATIC
VOID
PrepareForVmrun (
    IN OUT ROOT_CONTEXT* SharedContext,
    IN UINT32 ProcessorNumber,
    IN CONST GUEST_CONTEXT* ContextRecord
    )
{
    PER_CPU_DATA* cpu;
    PT_ENTRY_4KB* localApicNestedPte;
    PAGING_STRUCTURES* nestedPageTables;

    cpu = &SharedContext->Cpus[ProcessorNumber];

    //
    // APIC access interception related settings. Those are only needed for BSP.
    // The pointer to the NPT PTE for local APIC page is only needed for the BPS
    // because only BSP changes its contents. BPS needs a separate NPTS from the
    // other processors to prevent racing with and impacting the other processors
    // during changes of it (ie, the NPT PTE for local APIC page).
    //
    if (ProcessorNumber == 0)
    {
        ADDRESS_TRANSLATION_HELPER apicBase;

        apicBase.AsUInt64 = GetLocalApicBaseAddress();
        localApicNestedPte = &SharedContext->Svm.NestedPtForBsp[apicBase.AsIndex.Pt];
        nestedPageTables = &SharedContext->Svm.NestedPageTablesForBsp;
    }
    else
    {
        localApicNestedPte = NULL;
        nestedPageTables = &SharedContext->Svm.NestedPageTables;
    }

    //
    // For INIT-SIPI-SIPI handling. Redirect INIT to #SX, and intercept #SX.
    // See "15.30.1 VM_CR MSR (C001_0114h)".
    //
    AsmMsrOr64(SVM_MSR_VM_CR, VM_CR_R_INIT);
    cpu->GuestVmcb.ControlArea.InterceptException = BIT30;  // #SX

    //
    // Intercept CPUID for hypervisor detection etc. Intercept of VMRUN is required
    // by the processor, but this project does not handle this #VMEXIT. To also
    // note that, the hypervisor should intercept MSR access from the guest to
    // protect those required for SVM and the host from being modified. This
    // project does not do this. This work is left for readers.
    //
    cpu->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;

    //
    // Same hard-coded ASID for all processors. No need to use different ones as
    // this project only have the single guest.
    //
    cpu->GuestVmcb.ControlArea.GuestAsid = 1;

    //
    // Enable NTPs.
    //
    cpu->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    cpu->GuestVmcb.ControlArea.NCr3 = (UINT64)nestedPageTables;

    //
    // Set up the guest state using the captured context.
    //
    cpu->GuestVmcb.StateSaveArea.GdtrBase = ContextRecord->Gdtr.Base;
    cpu->GuestVmcb.StateSaveArea.GdtrLimit = ContextRecord->Gdtr.Limit;
    cpu->GuestVmcb.StateSaveArea.IdtrBase = ContextRecord->Idtr.Base;
    cpu->GuestVmcb.StateSaveArea.IdtrLimit = ContextRecord->Idtr.Limit;

    cpu->GuestVmcb.StateSaveArea.CsLimit = (UINT32)__segmentlimit(ContextRecord->SegCs);
    cpu->GuestVmcb.StateSaveArea.DsLimit = (UINT32)__segmentlimit(ContextRecord->SegDs);
    cpu->GuestVmcb.StateSaveArea.EsLimit = (UINT32)__segmentlimit(ContextRecord->SegEs);
    cpu->GuestVmcb.StateSaveArea.SsLimit = (UINT32)__segmentlimit(ContextRecord->SegSs);
    cpu->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    cpu->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    cpu->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    cpu->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    cpu->GuestVmcb.StateSaveArea.CsAttrib = GetSegmentAccessRight(ContextRecord->SegCs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.DsAttrib = GetSegmentAccessRight(ContextRecord->SegDs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.EsAttrib = GetSegmentAccessRight(ContextRecord->SegEs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.SsAttrib = GetSegmentAccessRight(ContextRecord->SegSs, ContextRecord->Gdtr.Base);

    cpu->GuestVmcb.StateSaveArea.Efer = ContextRecord->Efer;
    cpu->GuestVmcb.StateSaveArea.GPat = ContextRecord->GPat;
    cpu->GuestVmcb.StateSaveArea.Cr0 = ContextRecord->Cr0;
    cpu->GuestVmcb.StateSaveArea.Cr2 = ContextRecord->Cr2;
    cpu->GuestVmcb.StateSaveArea.Cr3 = ContextRecord->Cr3;
    cpu->GuestVmcb.StateSaveArea.Cr4 = ContextRecord->Cr4;
    cpu->GuestVmcb.StateSaveArea.Rflags = ContextRecord->Rflags;
    cpu->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    cpu->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    __svm_vmsave((UINTN)&cpu->GuestVmcb);

    //
    // Pass values to the host through the host stack address.
    //
    cpu->HostStack.Layout.Params.GuestVmcbPa = (UINT64)&cpu->GuestVmcb;
    cpu->HostStack.Layout.Params.SharedContext = SharedContext;
    cpu->HostStack.Layout.Params.ProcessorNumber = ProcessorNumber;
    cpu->HostStack.Layout.Params.Reserved1 = MAX_UINT32;

    //
    // Configure VM_HSAVE_PA MSR. See "15.30.4 VM_HSAVE_PA MSR (C001_0117h)""
    //
    AsmWriteMsr64(SVM_MSR_VM_HSAVE_PA, (UINT64)&cpu->HostStateArea[0]);

    //
    // Initialize state variables.
    //
    cpu->States.Guest.ProcessorNumber = ProcessorNumber;
    cpu->States.Guest.ApicId = GetApicId();
    cpu->States.Guest.ActivityState = GuestStateActive;
    cpu->States.Guest.ApicAccessState = ApicAccessPassthrough;
    cpu->States.Svm.LocalApicNestedPte = localApicNestedPte;

    DEBUG((DEBUG_VERBOSE,
           "CPU %d, APIC ID %d, Log @ %p\n",
           ProcessorNumber,
           cpu->States.Guest.ApicId,
           &cpu->Logs));

    //
    // Switch the current execution environment for the host.
    //
    InitializeHostData(&cpu->HostX64Data, &SharedContext->HostX64);
    SwitchToHostContext(&SharedContext->HostX64, &cpu->HostX64Data);
    __svm_vmsave((UINTN)&cpu->HostVmcb);
}

/**
 * @brief Tests whether the specified hypervisor is present.
 */
STATIC
BOOLEAN
IsHypervisorPresent (
    CONST CHAR8* HyperVisorName
    )
{
    UINT32 registers[4];   // EAX, EBX, ECX, and EDX
    CHAR8 vendorId[13];

    //
    // When our hypervisor or ones that is compatible with the Hypervisor Top
    // Level Functional Specification is installed, CPUID leaf 40000000h will
    // return hypervisor vendor ID signature in EBX, ECX, and EDX.
    //
    AsmCpuid(CPUID_HV_VENDOR_AND_MAX_FUNCTIONS, NULL, &registers[1], &registers[2], &registers[3]);
    CopyMem(vendorId + 0, &registers[1], sizeof(registers[1]));
    CopyMem(vendorId + 4, &registers[2], sizeof(registers[2]));
    CopyMem(vendorId + 8, &registers[3], sizeof(registers[3]));
    vendorId[12] = CHAR_NULL;

    return (AsciiStrCmp(vendorId, HyperVisorName) == 0);
}

/**
 * @brief Virtualizes the current processor.
 */
STATIC
VOID
EFIAPI
VirtualizeProcessor (
    IN OUT VOID* Context
    )
{
    GUEST_CONTEXT guestContext;

    //
    // Enable SVM and capture the current context, which will be resumed on the
    // VMRUN.
    //
    AsmMsrOr64(MSR_IA32_EFER, EFER_SVME);
    CAPTURE_CONTEXT(&guestContext);

    //
    // On the first run, the hypervisor is not installed and the virtualization
    // is performed. Then, on VMRUN, the guest starts execution from here again
    // and detects the hypervisor, exiting from this function.
    //
    if (IsHypervisorPresent("HelloAmdHv  ") == FALSE)
    {
        UINT32 processorNum;
        ROOT_CONTEXT* context;

        context = (ROOT_CONTEXT*)Context;
        processorNum = GetCurrentProcessorNumber();
        DEBUG((DEBUG_INFO, "Virtualizing the processor %u\n", processorNum));

        PrepareForVmrun(context, processorNum, &guestContext);
        AsmLaunchVm(&context->Cpus[processorNum].HostStack.Layout.Params);
        ASSERT(FALSE);
        CpuDeadLoop();
    }
    DEBUG((DEBUG_INFO, "Virtualized the processor\n"));
}

/**
 * @brief Splits large page PDE into 4KB PTEs.
 */
STATIC
VOID
Split2MbPage (
    IN OUT PD_ENTRY_2MB* PageDirectoryEntry,
    OUT PT_ENTRY_4KB* PageTable
    )
{
    UINT64 baseAddress;

    //
    // Attempt to split non-large page is a bug.
    //
    ASSERT(PageDirectoryEntry->Bits.LargePage != FALSE);

    //
    // Those bits are expected to be as configured in SetupIdentityMapping.
    // Because the entry is expected to be one of NPTs, the User bit is expected
    // to be set.
    //
    ASSERT(PageDirectoryEntry->Bits.Valid != FALSE);
    ASSERT(PageDirectoryEntry->Bits.Write != FALSE);
    ASSERT(PageDirectoryEntry->Bits.User != FALSE);
    ASSERT(PageDirectoryEntry->Bits.WriteThrough == FALSE);
    ASSERT(PageDirectoryEntry->Bits.CacheDisable == FALSE);
    ASSERT(PageDirectoryEntry->Bits.Pat == FALSE);

    //
    // Fill out the page table.
    //
    baseAddress = ((UINT64)PageDirectoryEntry->Bits.PageFrameNumber << 21);
    for (UINT64 ptIndex = 0; ptIndex < PAGE_TABLE_ENTRY_COUNT; ++ptIndex)
    {
        PageTable[ptIndex].Uint64 = baseAddress;
        PageTable[ptIndex].Bits.Valid = TRUE;
        PageTable[ptIndex].Bits.Write = TRUE;
        PageTable[ptIndex].Bits.User = TRUE;
        baseAddress += SIZE_4KB;
    }

    //
    // The PDE should no longer indicates 2MB large page.
    //
    PageDirectoryEntry->Uint64 = (UINT64)PageTable;
    PageDirectoryEntry->Bits.LargePage = FALSE;
    PageDirectoryEntry->Bits.Valid = TRUE;
    PageDirectoryEntry->Bits.Write = TRUE;
    PageDirectoryEntry->Bits.User = TRUE;
}

/**
 * @brief Initializes the paging structures by building identically mapped
 *      translations.
 *
 * @details This function assumes that PA0 of the PAT register is configured for
 *      the write-back memory type and does not set PAT, PCD or PWT bits.
 */
STATIC
VOID
SetupIdentityMapping (
    OUT PAGING_STRUCTURES* PagingStructures,
    IN BOOLEAN NestedPageTables
    )
{
    PML4_ENTRY_2MB* pml4;
    PDP_ENTRY_2MB* pdpt;
    PD_ENTRY_2MB* pd;
    UINT32 pml4Index;
    UINT64 pa;
    BOOLEAN userAccessible;

    ZeroMem(PagingStructures, sizeof(*PagingStructures));

    //
    // All nested page table entries are configured as user-accessible. See
    // "15.25.5 Nested Table Walk" for the requirement. For the standard paging
    // structures, the pages are not accessible from user, because the indent of
    // this function is to use for the host page tables, which should not need
    // any user access.
    //
    userAccessible = (NestedPageTables != FALSE);

    //
    // Fill out PML4, PDPT, PD. The PD entries are configured for large pages.
    //
    pa = 0;

    pml4Index = 0;
    pml4 = PagingStructures->Pml4;
    pdpt = PagingStructures->Pdpt[pml4Index];

    pml4[0].Bits.Valid = TRUE;
    pml4[0].Bits.Write = TRUE;
    pml4[0].Bits.User = userAccessible;
    pml4[0].Bits.PageFrameNumber = (UINT64)pdpt >> EFI_PAGE_SHIFT;

    for (UINT32 pdptIndex = 0; pdptIndex < PAGE_TABLE_ENTRY_COUNT; ++pdptIndex)
    {
        pd = PagingStructures->Pd[pml4Index][pdptIndex];

        pdpt[pdptIndex].Bits.Valid = TRUE;
        pdpt[pdptIndex].Bits.Write = TRUE;
        pdpt[pdptIndex].Bits.User = userAccessible;
        pdpt[pdptIndex].Bits.PageFrameNumber = (UINT64)pd >> EFI_PAGE_SHIFT;

        for (UINT32 pdIndex = 0; pdIndex < PAGE_TABLE_ENTRY_COUNT; ++pdIndex)
        {
            pd[pdIndex].Bits.Valid = TRUE;
            pd[pdIndex].Bits.Write = TRUE;
            pd[pdIndex].Bits.User = userAccessible;
            pd[pdIndex].Bits.LargePage = TRUE;
            pd[pdIndex].Bits.PageFrameNumber = pa >> 21;

            pa += SIZE_2MB;
        }
    }
}

/**
 * @brief Initialize the system global host environment object.
 */
STATIC
VOID
InitializeHostSharedData (
    OUT SHARED_HOST_DATA* SharedHostData
    )
{
    UINT64 handlerBase;

    SharedHostData->ProcessorCount = GetActiveProcessorCount();

    //
    // Setup the identitiy page tables for the host.
    //
    SetupIdentityMapping(&SharedHostData->PagingStructures, FALSE);
    SharedHostData->Cr3 = (UINT64)&SharedHostData->PagingStructures.Pml4[0];

    //
    // Get the beginning of the AsmDefaultExceptionHandlers to index.
    // Fill out all IDT entries.
    //
    handlerBase = (UINT64)&AsmDefaultExceptionHandlers;
    for (UINT32 i = 0; i < IDT_ENTRY_COUNT; ++i)
    {
        UINT64 sizeOfHandler;
        UINT64 handlerAddress;

        //
        // Compute the address of AsmDefaultExceptionHandlers[i]. Each stub
        // function is 9 bytes up to 0x7f, and 12 bytes after that.
        //
        if (i < 0x80)
        {
            sizeOfHandler = 9;
        }
        else
        {
            sizeOfHandler = 12;
        }
        handlerAddress = (handlerBase + i * sizeOfHandler);

        //
        // Fill out the IDT entry. The type is 32-bit Interrupt gate: 0x8E
        //  P=1, DPL=00b, S=0, type=1110b => type_attr=1000_1110b=0x8E)
        //
        SharedHostData->Idt[i].Bits.OffsetLow = (UINT16)handlerAddress;
        SharedHostData->Idt[i].Bits.OffsetHigh = (UINT16)(handlerAddress >> 16);
        SharedHostData->Idt[i].Bits.OffsetUpper = (UINT32)(handlerAddress >> 32);
        SharedHostData->Idt[i].Bits.Selector = AsmReadCs();
        SharedHostData->Idt[i].Bits.GateType = 0x8E;
    }

    SharedHostData->Idtr.Base = (UINT64)&SharedHostData->Idt[0];
    SharedHostData->Idtr.Limit = sizeof(SharedHostData->Idt) - 1;
}

/**
 * @brief Initialize the root context object.
 */
STATIC
VOID
InitializeSharedContext (
    OUT ROOT_CONTEXT* Context
    )
{
    ADDRESS_TRANSLATION_HELPER apicBase;
    PD_ENTRY_2MB* pde;

    DEBUG((DEBUG_VERBOSE, "Root context at %p\n", Context));

    InitializeHostSharedData(&Context->HostX64);
    SetupIdentityMapping(&Context->Svm.NestedPageTables, TRUE);
    SetupIdentityMapping(&Context->Svm.NestedPageTablesForBsp, TRUE);

    //
    // Split the nested PDE to get 4KB nested PTE for the local APIC address.
    // This 4KB page is required because this project needs to intercept access
    // to the local APIC page to detect INIT and SIPI. See HandleNestedPageFault
    // and HandleDebugException.
    //
    apicBase.AsUInt64 = GetLocalApicBaseAddress();
    pde = &Context->Svm.NestedPageTablesForBsp.Pd
            [apicBase.AsIndex.Pml4][apicBase.AsIndex.Pdpt][apicBase.AsIndex.Pd];
    ASSERT(pde->Bits.LargePage != FALSE);
    Split2MbPage(pde, Context->Svm.NestedPtForBsp);
}

/**
 * @brief Prevents the platform from relocating the image at boot-to-runtime
 *      transition.
 *
 * @details EDK2 relocates PE images of the runtime drivers based on their
 *      relocation information when prior to transition to runtime. This can
 *      host code as it never runs with the runtime page table and instead
 *      runs with the page tables that is equivalent to that of boot-time. This
 *      brokage can be observed as #PF on assertion failure in the host for
 *      example. This function nullifies the NT header to make the platform fail
 *      to find relocation information of this module. For why this works, see
 *      RuntimeDriverSetVirtualAddressMap in the EDK2 repo.
 */
STATIC
VOID
SuppressImageRelocation (
    IN UINT64 ImageBase
    )
{
    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION hdr;
    EFI_IMAGE_DOS_HEADER* dosHdr;

    dosHdr = (EFI_IMAGE_DOS_HEADER*)ImageBase;
    ASSERT(dosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE);

    hdr.Pe32Plus = (EFI_IMAGE_NT_HEADERS64*)(((CHAR8*)dosHdr) + dosHdr->e_lfanew);
    ASSERT(hdr.Pe32Plus->Signature == EFI_IMAGE_NT_SIGNATURE);
    hdr.Pe32Plus->Signature = 0;
}

/**
 * @brief Checks whether the system is compatible with this project.
 */
STATIC
BOOLEAN
IsSystemCompatible (
    VOID
    )
{
    UINT32 regEbx;
    UINT32 regEcx;
    UINT32 regEdx;
    CPUID_AMD_EXTENDED_CPU_SIG_ECX extendedSig;
    MSR_IA32_PAT_REGISTER pat;

    //
    // Test if the current processor is AMD one. An AMD processor should return
    // "AuthenticAMD" from CPUID function 0. See "Function 0h-Maximum Standard
    // Function Number and Vendor String".
    //
    AsmCpuid(CPUID_SIGNATURE, NULL, &regEbx, &regEcx, &regEdx);
    if ((regEbx != CPUID_SIGNATURE_AUTHENTIC_AMD_EBX) ||
        (regEcx != CPUID_SIGNATURE_AUTHENTIC_AMD_ECX) ||
        (regEdx != CPUID_SIGNATURE_AUTHENTIC_AMD_EDX))
    {
        DEBUG((DEBUG_ERROR, "Not an AMD processor\n"));
        return FALSE;
    }

    //
    // Test if the SVM feature is supported by the current processor. See
    // "Enabling SVM" and "CPUID Fn8000_0001_ECX Feature Identifiers".
    //
    AsmCpuid(CPUID_EXTENDED_CPU_SIG, NULL, NULL, &extendedSig.Uint32, NULL);
    if (extendedSig.Bits.SVM == 0)
    {
        DEBUG((DEBUG_ERROR, "AMD-V not supported\n"));
        return FALSE;
    }

    //
    // Test if the Nested Page Tables feature is supported by the current
    // processor. See "Enabling Nested Paging" and "CPUID Fn8000_000A_EDX SVM
    // Feature Identification".
    //
    AsmCpuid(CPUID_SVM_FEATURES, NULL, NULL, NULL, &regEdx);
    if ((regEdx & CPUID_SVM_FEATURES_EDX_NP) == 0)
    {
        DEBUG((DEBUG_ERROR, "Nested page tables not supported\n"));
        return FALSE;
    }

    //
    // Test if the SVM feature can be enabled. When VM_CR.SVMDIS is set,
    // EFER.SVME cannot be 1; therefore, SVM cannot be enabled. See
    // "Enabling SVM".
    //
    if ((AsmReadMsr64(SVM_MSR_VM_CR) & VM_CR_SVMDIS) != 0)
    {
        DEBUG((DEBUG_ERROR, "AMD-V cannot be enabled\n"));
        return FALSE;
    }

    //
    // This project does not support x2APIC systems. Support of those systems
    // require MSR-based APIC access for intercepting INIT and SIPI. This is
    // fairly a simple task and left for readers :-) This can be tested on VMware.
    // The author opted out support because was unable to test on baremetal.
    //
    if (GetApicMode() == LOCAL_APIC_MODE_X2APIC)
    {
        DEBUG((DEBUG_ERROR, "x2APIC is not supported\n"));
        return FALSE;
    }

    //
    // This project expects the PAT register to have the default value,
    // specifically that PA0 indicates the write-back type. This is solely to
    // simplify page table structures setup. See "7.8.2 PAT Indexing".
    //
    pat.Uint64 = AsmReadMsr64(MSR_IA32_PAT);
    if (pat.Bits.PA0 != MTRR_CACHE_WRITE_BACK)
    {
        DEBUG((DEBUG_ERROR, "PAT register#0 is not configured for write back\n"));
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Find the image base address of the given address.
 */
STATIC
UINT64
GetImageBase (
    IN UINT64 SearchBaseAddress
    )
{
    UINT64 base;

    base = SearchBaseAddress & ~EFI_PAGE_MASK;
    for (UINT32 i = 0; i < 0x100; ++i)
    {
        if (*(UINT16*)base == EFI_IMAGE_DOS_SIGNATURE)
        {
            return base;
        }

        base -= SIZE_4KB;
    }
    return 0;
}

/**
 * @brief The entry point of this driver.
 */
EFI_STATUS
EFIAPI
HelloAmdHvDxeInitialize (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    EFI_STATUS status;
    UINT64 imageBase;
    UINT64 allocBytes;
    ROOT_CONTEXT* context;

    context = NULL;

    //
    // Find the image base address and debug print it. This is useful for debugging.
    //
    imageBase = GetImageBase((UINT64)&HelloAmdHvDxeInitialize);
    ASSERT(imageBase != 0);

    DEBUG((DEBUG_VERBOSE, "Loading the driver at %llx\n", imageBase));

    //
    // Make sure the system has supported hardware and system configurations.
    //
    if (IsSystemCompatible() == FALSE)
    {
        status = EFI_UNSUPPORTED;
        goto Exit;
    }

    //
    // Make the MP protocol available for use.
    //
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID**)&g_MpServices);
    if (EFI_ERROR(status))
    {
        DEBUG((DEBUG_ERROR, "MP protocol unsupported : %r\n", status));
        goto Exit;
    }

    //
    // Initialize the expected SIPI count that occurs at runtime. That is the
    // number of APs multiplied by 2 because the operating system sends two SIPIs.
    //
    g_RemainingSipiCount = (GetActiveProcessorCount() - 1) * 2;

    //
    // Allocate and initialize the global context object, then virtualize all
    // processors.
    //
    allocBytes = sizeof(ROOT_CONTEXT) + GetActiveProcessorCount() * sizeof(PER_CPU_DATA);
    context = AllocateRuntimePages(EFI_SIZE_TO_PAGES(allocBytes));
    if (context == NULL)
    {
        status = EFI_OUT_OF_RESOURCES;
        goto Exit;
    }
    ZeroMem(context, allocBytes);
    InitializeSharedContext(context);
    InitializeHostDebugFacility(context);

    RunOnAllProcessors(VirtualizeProcessor, context);

    //
    // Finally, prevent from relocation happening.
    //
    SuppressImageRelocation(imageBase);
    status = EFI_SUCCESS;

Exit:
    if (EFI_ERROR(status))
    {
        if (context != NULL)
        {
            FreePages(context, EFI_SIZE_TO_PAGES(allocBytes));
        }
    }
    return status;
}
