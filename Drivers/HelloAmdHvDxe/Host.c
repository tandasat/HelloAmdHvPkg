/**
 * @file Host.c
 *
 * @brief Implements the hypervisor logic.
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include "HelloAmdHv.h"

#if ENABLE_HOST_MEMORY_LOGGING != 0

//
// DEBUG that logs messages into a memory buffer.
//
#if !defined(MDEPKG_NDEBUG)
#define HOST_DEBUG_INTERNAL(Context, ...)   LogToMemory((Context), ##__VA_ARGS__)
#define HOST_DEBUG(Expression)              HOST_DEBUG_INTERNAL Expression
#else
#define HOST_DEBUG(Expression)
#endif

//
// ASSERT that logs messages into a memory buffer.
//
#if !defined(MDEPKG_NDEBUG)
#define HOST_ASSERT(Expression) \
    do \
    { \
        if (!(Expression)) \
        { \
            LogToMemory(NULL, "ASSERT@%d APIC %d: %a\n", __LINE__, GetApicId(), #Expression); \
            CpuDeadLoop(); \
        } \
    } while (FALSE)
#else
#define HOST_ASSERT(Expression)
#endif

#else

//
// ENABLE_HOST_MEMORY_LOGGING is zero. Use the standard logging facility.
//
#define HOST_DEBUG_INTERNAL(Context, ...)   _DEBUG_PRINT(DEBUG_ERROR, __VA_ARGS__)
#define HOST_DEBUG(Expression)              HOST_DEBUG_INTERNAL Expression
#define HOST_ASSERT(Expression)             ASSERT(Expression)

#endif

//
// The layout of the stack address passed to HandleVmExit.
//
typedef struct _HOST_VMEXIT_STACK
{
    GUEST_REGISTERS GuestRegisters;
    HOST_STACK_BASED_PARAMETERS Params;
} HOST_VMEXIT_STACK;

//
// The layout of the stack address passed to HandleHostException.
//
typedef struct _HOST_EXCEPTION_STACK
{
    GUEST_REGISTERS GuestRegisters;
    UINT64 InterruptNumber;
    UINT64 ErrorCode;
    UINT64 Rip;
    UINT64 Cs;
    UINT64 Rflags;
} HOST_EXCEPTION_STACK;

//
// The system global log entry count. Useful for human to follow the order of
// logs across all processors (log buffers).
//
STATIC volatile UINT32 g_LogIndex;

//
// TRUE if the APIC interception has ever been enabled, or FALSE.
//
STATIC BOOLEAN g_LocalApicIoInterceptStarted;

/**
 * @brief Resets the system. This can be called from the host at any time.
 */
STATIC
VOID
CpuReset (
    VOID
    )
{
    g_ResetSystemPhys(EfiResetCold, EFI_ABORTED, 0, NULL);
}

/**
 * @brief Stores the log message to the provided buffer.
 *
 * @details This function is not safe to call concurrently against the same buffer.
 */
STATIC
VOID
LogToMemory (
    IN OUT HOST_CONTEXT* Context OPTIONAL,
    IN CONST CHAR8* FormatString,
    ...
    )
{
    UINT32 index;
    VA_LIST args;
    MEMORY_LOGS* logs;

    logs = (Context == NULL) ? g_GlobalLogBuffer : &Context->Cpu->Logs;

    //
    // Pick up the index of log buffer to write to. The index go back to zero
    // if it overflows.
    //
    index = InterlockedIncrement(&logs->NextPosition) - 1;
    if (index >= ARRAY_SIZE(logs->Entries))
    {
        logs->NextPosition = 0;
        index = 0;
    }

    //
    // Take the system global index.
    //
    logs->Entries[index].GlobalIndex = InterlockedIncrement(&g_LogIndex);

    //
    // Zero out the current log entry instead of leaving old data if any. Then,
    // write the log message into it.
    //
    ZeroMem(logs->Entries[index].Message, sizeof(logs->Entries[index].Message));

    VA_START(args, FormatString);
    AsciiVSPrint(logs->Entries[index].Message,
                 sizeof(logs->Entries[index].Message),
                 FormatString,
                 args);
    VA_END(args);

    //
    // If EFI variables are usable, write back the whole 4KB log buffer to it.
    //
    if (g_SetVariablePhys != NULL)
    {
        EFI_STATUS status;
        CHAR16 variableName[16];
        UINT32 processorNumber;

        processorNumber = (Context == NULL) ? 0 : Context->Cpu->States.Guest.ProcessorNumber;
        UnicodeSPrint(variableName, sizeof(variableName), L"Log#%d", processorNumber);
        status = g_SetVariablePhys(variableName,
                                   &g_LogGuid,
                                   EFI_VARIABLE_NON_VOLATILE |
                                   EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                   EFI_VARIABLE_RUNTIME_ACCESS,
                                   sizeof(*logs),
                                   logs);
        if (EFI_ERROR(status))
        {
            CpuDeadLoop();
            CpuReset();
        }
    }
}

/**
 * @brief Enables or disables direct access to local APIC from the guest.
 *
 * @details If direct access is disabled, the local APIC page in GPA is mapped
 *      to unrelated buffer ShadowLocalApicPage using NPTs, hence, writing to
 *      and reading from local APIC page will not have any side-effects as it
 *      normally would (ie, issueing IPI).
 */
STATIC
VOID
EnableLocalApicPassthrough (
    IN OUT HOST_CONTEXT* Context,
    IN BOOLEAN Enable
    )
{
    UINT64 address;

    address = (Enable != FALSE) ? GetLocalApicBaseAddress() :
                (UINT64)&Context->Root->Svm.ShadowLocalApicPage[0];

    HOST_ASSERT(Context->Cpu->States.Svm.LocalApicNestedPte->Bits.PageFrameNumber != (address >> 12));
    Context->Cpu->States.Svm.LocalApicNestedPte->Bits.PageFrameNumber = (address >> 12);
    Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
}

/**
 * @brief Enables or disables interception of local APIC access.
 */
STATIC
VOID
EnableLocalApicIoIntercept (
    IN OUT PER_CPU_DATA* Cpu,
    IN BOOLEAN Enable
    )
{
    HOST_ASSERT(Cpu->States.Svm.LocalApicNestedPte->Bits.Write != (Enable == FALSE));
    Cpu->States.Svm.LocalApicNestedPte->Bits.Write = (Enable == FALSE);
    Cpu->GuestVmcb.ControlArea.TlbControl = 1;
}

/**
 * @brief Enables or disables single stepping of the guest.
 */
STATIC
VOID
EnableSingleStep (
    IN OUT PER_CPU_DATA* Cpu,
    IN BOOLEAN Enable
    )
{
    //
    // Set or clear TF and #DB interception.
    //
    if (Enable != FALSE)
    {
        HOST_ASSERT((Cpu->GuestVmcb.StateSaveArea.Rflags & BIT8) == 0);
        HOST_ASSERT((Cpu->GuestVmcb.ControlArea.InterceptException & BIT1) == 0);

        Cpu->GuestVmcb.StateSaveArea.Rflags |= BIT8;
        Cpu->GuestVmcb.ControlArea.InterceptException |= BIT1;
    }
    else
    {
        HOST_ASSERT((Cpu->GuestVmcb.StateSaveArea.Rflags & BIT8) != 0);
        HOST_ASSERT((Cpu->GuestVmcb.ControlArea.InterceptException & BIT1) != 0);

        Cpu->GuestVmcb.StateSaveArea.Rflags &= ~BIT8;
        Cpu->GuestVmcb.ControlArea.InterceptException &= ~BIT1;
    }

    //
    // Clear the clean bit for intercepts.
    //
    Cpu->GuestVmcb.ControlArea.VmcbClean &= ~BIT0;
}

/**
 * @brief Loops up the processor number for the APIC ID.
 */
STATIC
UINT32
ConvertApicIdToProcessorNumber (
    IN CONST ROOT_CONTEXT* Context,
    IN UINT32 ApicId
    )
{
    for (UINT32 i = 0; i < Context->HostX64.ProcessorCount; ++i)
    {
        if (Context->Cpus[i].States.Guest.ApicId == ApicId)
        {
            return i;
        }
    }
    return MAX_UINT32;
}

/**
 * @brief Emulates write access to the low ICR of the local APIC. This is done
 *      to emulate INIT-SIPI-SIPI without actually INIT-ing APs.
 */
STATIC
VOID
EmulateIcrAccess (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT32 icrLow;
    UINT32 destination;
    UINT32 destProcessorNum;
    UINT8 vector;
    UINT8 mode;
    PER_CPU_DATA* destCpu;

    //
    // Get the value the guest tried to write to the ICR.
    //
    icrLow = *(UINT32*)&Context->Root->Svm.ShadowLocalApicPage[XAPIC_ICR_LOW_OFFSET];
    mode = (icrLow >> 8) & 0b111;

    //
    // Bail out and just emulate if this is neither INIT nor SIPI. No special handling.
    //
    if ((mode != LOCAL_APIC_DELIVERY_MODE_INIT) &&
        (mode != LOCAL_APIC_DELIVERY_MODE_STARTUP))
    {
        goto Exit;
    }

    //
    // Get more details of this access and log it.
    //
    vector = (UINT8)icrLow;
    destination = MmioBitFieldRead32(GetLocalApicBaseAddress() + XAPIC_ICR_HIGH_OFFSET,
                                     24,
                                     31);
    destProcessorNum = ConvertApicIdToProcessorNumber(Context->Root, destination);
    HOST_ASSERT(destProcessorNum != MAX_UINT32);
    HOST_DEBUG((Context,
                "#DB @ %016lx ICR:%08x Dst:%d Mod:%d Vec:0x%02x\n",
                Context->Cpu->GuestVmcb.StateSaveArea.Rip,
                icrLow,
                destination,
                mode,
                vector));

    if (mode == LOCAL_APIC_DELIVERY_MODE_INIT)
    {
        //
        // Discard previous SIPI vector in case.
        //
        destCpu = &Context->Root->Cpus[destProcessorNum];
        destCpu->States.Guest.SipiVector = 0;
        InterlockedCompareExchange32(
                    (volatile UINT32*)&destCpu->States.Guest.ActivityState,
                    destCpu->States.Guest.ActivityState,
                    GuestStateWaitForSipi);
        HOST_DEBUG((Context, "INIT emulated\n"));
    }
    else if (mode == LOCAL_APIC_DELIVERY_MODE_STARTUP)
    {
        UINT32 remainingSipi;

        //
        // Let the destination CPU know the SIPI vector to startup.
        //
        destCpu = &Context->Root->Cpus[destProcessorNum];
        destCpu->States.Guest.SipiVector = vector;
        InterlockedCompareExchange32(
                    (volatile UINT32*)&destCpu->States.Guest.ActivityState,
                    destCpu->States.Guest.ActivityState,
                    GuestStateSipiIssued);

        //
        // During the runtime, only two SIPI by the operating system is expected.
        // Count SIPI and end APIC access intercepting if the expected number of
        // SIPI was processed.
        //
        remainingSipi = InterlockedDecrement(&g_RemainingSipiCount);
        HOST_DEBUG((Context, "SIPI emulated. %d more expected\n", remainingSipi));
        if (remainingSipi == 0)
        {
            EnableLocalApicIoIntercept(Context->Cpu, FALSE);
            HOST_DEBUG((Context, "End of APIC interception\n"));
        }
    }

Exit:
    //
    // Finally, emulate write to ICR.
    //
    MmioWrite32(GetLocalApicBaseAddress() + XAPIC_ICR_LOW_OFFSET, icrLow);
}

/**
 * @brief Handles #VMEXIT due to #DB.
 */
STATIC
VOID
HandleDebugException (
    IN OUT HOST_CONTEXT* Context
    )
{
    ASSERT(EfiGoneVirtual() != FALSE);
    ASSERT(Context->Cpu->States.Guest.ProcessorNumber == 0);

    //
    // We intercept #DB only when nested page fault is detected on local APIC
    // address, meaning local APIC access interception has been disabled. Reenable
    // it, and also, disable single stepping.
    //
    EnableLocalApicIoIntercept(Context->Cpu, TRUE);
    EnableSingleStep(Context->Cpu, FALSE);

    //
    // Bail out if the previous access was not against ICR. Otherwise, APIC
    // access passthrough is suspended and ICR access is pending. Reenable
    // passthrough and emulate ICR access.
    //
    if (Context->Cpu->States.Guest.ApicAccessState != ApicAccessPending)
    {
        return;
    }

    Context->Cpu->States.Guest.ApicAccessState = ApicAccessPassthrough;
    EnableLocalApicPassthrough(Context, TRUE);
    EmulateIcrAccess(Context);
}

/**
 * @brief Handles #VMEXIT due to nested page fault.
 */
STATIC
VOID
HandleNestedPageFault (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT64 faultAddress;
    UINT64 faultPageOffset;

    ASSERT(EfiGoneVirtual() != FALSE);
    ASSERT(Context->Cpu->States.Guest.ProcessorNumber == 0);

    //
    // If this is a write to the APIC IRC, temporary deactivate local APIC to
    // prevent the command being actually issued without having a chance to
    // inspect what it is.
    //
    faultAddress = Context->Cpu->GuestVmcb.ControlArea.ExitInfo2;
    faultPageOffset = faultAddress & EFI_PAGE_MASK;
    if (faultPageOffset == XAPIC_ICR_LOW_OFFSET)
    {
        HOST_ASSERT(Context->Cpu->States.Guest.ApicAccessState == ApicAccessPassthrough);
        Context->Cpu->States.Guest.ApicAccessState = ApicAccessPending;
        EnableLocalApicPassthrough(Context, FALSE);
    }

    //
    // Disable interception of local APIC access to let the guest complete it.
    // Enable single stepping to get #VMEXIT on completion of access so that we
    // can reenable local APIC interception.
    //
    EnableLocalApicIoIntercept(Context->Cpu, FALSE);
    EnableSingleStep(Context->Cpu, TRUE);
}

/**
 * @brief Handles arrival of SIPI.
 */
STATIC
VOID
HandleStartupIpi (
    IN OUT HOST_CONTEXT* Context,
    IN UINT64 Vector
    )
{
    //
    // The guest state was updated by WaitForSipi when SIPI was received.
    //
    HOST_ASSERT(Context->Cpu->States.Guest.ActivityState == GuestStateActive);

    Context->Cpu->GuestVmcb.StateSaveArea.CsSelector = (UINT16)(Vector << 8);
    Context->Cpu->GuestVmcb.StateSaveArea.CsBase = Vector << 12;
    Context->Cpu->GuestVmcb.StateSaveArea.Rip = 0;
}

/**
 * @brief Waits for arrival of SIPI by polling the state field that gets updated
 *      by BSP when it issues SIPI (see EmulateIcrAccess).
 */
STATIC
UINT64
WaitForSipi (
    IN OUT HOST_CONTEXT* Context
    )
{
    HOST_DEBUG((Context,
                "APIC %d waiting for SIPI\n",
                Context->Cpu->States.Guest.ApicId));

    //
    // Wait until ActivityState becomes GuestStateSipiIssued. When it happends,
    // updates the ActivityState to GuestStateActive.
    //
    while (InterlockedCompareExchange32(
                    (volatile UINT32*)&Context->Cpu->States.Guest.ActivityState,
                    GuestStateSipiIssued,
                    GuestStateActive) != GuestStateSipiIssued)
    {
        CpuPause();
    }

    HOST_DEBUG((Context,
                "APIC %d received SIPI vector 0x%02x\n",
                Context->Cpu->States.Guest.ApicId,
                Context->Cpu->States.Guest.SipiVector));
    return Context->Cpu->States.Guest.SipiVector;
}

/**
 * @brief Handles INIT by emulating register resetting.
 */
STATIC
VOID
HandleInitSignal (
    IN OUT HOST_CONTEXT* Context
    )
{
    IA32_CR0 oldCr0;
    IA32_CR0 newCr0;
    CPUID_VERSION_INFO_EAX cpudEax;

    //
    // The guest can be any of those:
    // - GuestStateActive if #SX is delivered before BSP starts APIC interception (VMware),
    // - GuestStateWaitForSipi if #SX is delivered before BSP issueing SIPI (many cases), or
    // - GuestStateSipiIssued if SIPI is also issued before this processor receives #SX (rare race).
    //
    // Let the state transition to GuestStateActive -> GuestStateWaitForSipi if
    // applicable. Otherwise, leave it (ie, remain as it is).
    //
    InterlockedCompareExchange32(
                (volatile UINT32*)&Context->Cpu->States.Guest.ActivityState,
                GuestStateActive,
                GuestStateWaitForSipi);

    //
    // See "14.1.3 Processor Initialization State".
    //
    oldCr0.UintN = Context->Cpu->GuestVmcb.StateSaveArea.Cr0;
    newCr0.UintN = 0;
    newCr0.Bits.ET = 1;
    newCr0.Bits.CD = oldCr0.Bits.CD;
    newCr0.Bits.NW = oldCr0.Bits.NW;

    AsmCpuid(CPUID_VERSION_INFO, &cpudEax.Uint32, NULL, NULL, NULL);

    Context->Cpu->GuestVmcb.StateSaveArea.Cr0 = newCr0.UintN;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr2 = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr3 = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr4 = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Rflags = BIT1;
    Context->Cpu->GuestVmcb.StateSaveArea.Efer = EFER_SVME;
    Context->Cpu->GuestVmcb.StateSaveArea.Rip = 0xfff0;
    Context->Cpu->GuestVmcb.StateSaveArea.CsSelector = 0xf000;
    Context->Cpu->GuestVmcb.StateSaveArea.CsBase = 0xffff0000;
    Context->Cpu->GuestVmcb.StateSaveArea.CsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.CsAttrib = 0x9b;
    Context->Cpu->GuestVmcb.StateSaveArea.DsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.DsBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.DsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.DsAttrib = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.EsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.EsBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.EsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.EsAttrib = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.FsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.FsBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.FsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.FsAttrib = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.GsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GsBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.GsAttrib = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.SsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.SsBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.SsLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.SsAttrib = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.GdtrBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GdtrLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.IdtrBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.IdtrLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrAttrib = 0x82;
    Context->Cpu->GuestVmcb.StateSaveArea.TrSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.TrBase = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.TrLimit = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.TrAttrib = 0x8b;
    Context->Cpu->States.Guest.Registers->Rax = 0;
    Context->Cpu->States.Guest.Registers->Rdx = cpudEax.Uint32;
    Context->Cpu->States.Guest.Registers->Rbx = 0;
    Context->Cpu->States.Guest.Registers->Rcx = 0;
    Context->Cpu->States.Guest.Registers->Rbp = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Rsp = 0;
    Context->Cpu->States.Guest.Registers->Rdi = 0;
    Context->Cpu->States.Guest.Registers->Rsi = 0;
    Context->Cpu->States.Guest.Registers->R8 = 0;
    Context->Cpu->States.Guest.Registers->R9 = 0;
    Context->Cpu->States.Guest.Registers->R10 = 0;
    Context->Cpu->States.Guest.Registers->R11 = 0;
    Context->Cpu->States.Guest.Registers->R12 = 0;
    Context->Cpu->States.Guest.Registers->R13 = 0;
    Context->Cpu->States.Guest.Registers->R14 = 0;
    Context->Cpu->States.Guest.Registers->R15 = 0;
    AsmWriteDr0(0);
    AsmWriteDr1(0);
    AsmWriteDr2(0);
    AsmWriteDr3(0);
    Context->Cpu->GuestVmcb.StateSaveArea.Dr6 = 0xffff0ff0;
    Context->Cpu->GuestVmcb.StateSaveArea.Dr7 = 0x400;

    //
    // Clear TLB and related clean bits.
    //
    Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
    Context->Cpu->GuestVmcb.ControlArea.VmcbClean &= ~(BIT5 | BIT6 | BIT7 | BIT8 | BIT9);
}

/**
 * @brief Handles #SX, which is raised and intercept when INIT is received.
 */
STATIC
VOID
HandleSecurityException (
    IN OUT HOST_CONTEXT* Context
    )
{
    HOST_ASSERT(Context->Cpu->GuestVmcb.ControlArea.ExitInfo1 == 1);

    HOST_DEBUG((Context,
                "APIC %d INIT received (to be discarded = %d)\n",
                Context->Cpu->States.Guest.ApicId,
                Context->Cpu->States.Guest.DisgardInitSignal));

    //
    // HACK: Ignore INIT signals received after AP startup by the operating system.
    // This happens when INIT signals are sent prior to interception of APIC
    // access and is observed with VMware. When this happens, this processor
    // receives INIT again after AP startup (SIPI handling) because multiple INIT
    // #VMEXIT can be queued already. The sequence of the event looks like this:
    //  1. BSP sends INIT (say by firmware)
    //  2. AP receives #SX VMEXIT and enters the busy loop in WaitForSipi
    //  3. BSP sends INIT (say by the operating system)
    //  4. BSP sends SIPI
    //  5. AP detects SIPI, and resume the guest execution with VMRUN
    //  6. AP receives #SX VMEXIT immediately after VMRUN because of (3)
    //  7. If lucky, BSP sends the 2nd SIPI and the AP redo (5-6), or never get
    //     out from WaitForSipi.
    // This check discards (6) and prevents (7).
    //
    if (Context->Cpu->States.Guest.DisgardInitSignal != FALSE)
    {
        return;
    }

    //
    // Emulate INIT by resetting the registers and entering a polling loop to
    // wait arrival of SIPI. Once that happens, emulate AP startup with the SIPI
    // vector and finally let the guest continue.
    //
    HandleInitSignal(Context);
    HandleStartupIpi(Context, WaitForSipi(Context));
    Context->Cpu->States.Guest.DisgardInitSignal = TRUE;
}

/**
 * @brief Handles CPUID.
 */
STATIC
VOID
HandleCpuid (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT32 registers[4];   // EAX, EBX, ECX, and EDX
    UINT32 leaf;
    UINT32 subLeaf;

    //
    // Execute CPUID as requested.
    //
    leaf = (UINT32)Context->Cpu->States.Guest.Registers->Rax;
    subLeaf = (UINT32)Context->Cpu->States.Guest.Registers->Rcx;
    AsmCpuidEx(leaf, subLeaf, &registers[0], &registers[1], &registers[2], &registers[3]);

    switch (leaf)
    {
    case CPUID_VERSION_INFO:
        //
        // Indicate presence of a hypervisor by setting the bit that are
        // reserved for use by hypervisor to indicate guest status. See "CPUID
        // Fn0000_0001_ECX Feature Identifiers".
        //
        registers[2] |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
        break;

    case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
        //
        // Return a maximum supported hypervisor CPUID leaf range and a vendor
        // ID signature as required by the spec.
        //
        registers[0] = CPUID_HV_MAX;
        registers[1] = SIGNATURE_32('H', 'e', 'l', 'l');  // "HelloAmdHv  "
        registers[2] = SIGNATURE_32('o', 'A', 'm', 'd');
        registers[3] = SIGNATURE_32('H', 'v', ' ', ' ');
        break;

    case CPUID_EXTENDED_CPU_SIG:
        //
        // ECX[SVM] = 0
        //
        registers[2] &= ~CPUID_EXTENDED_CPU_SIG_ECX_SVM;
        break;

    default:
        break;
    }

    //
    // Update guest's GPRs with results.
    //
    Context->Cpu->States.Guest.Registers->Rax = registers[0];
    Context->Cpu->States.Guest.Registers->Rbx = registers[1];
    Context->Cpu->States.Guest.Registers->Rcx = registers[2];
    Context->Cpu->States.Guest.Registers->Rdx = registers[3];

    Context->Cpu->GuestVmcb.StateSaveArea.Rip = Context->Cpu->GuestVmcb.ControlArea.NRip;
}

/**
 * @brief Starts APIC access intercepting if needed.
 *
 * @details This function detects the conditions where the system is needed and
 *      ready for APIC access interception. APIC access interception cannot be
 *      started from the beginning due to firmware compability issues, specifically
 *      that, NMI during the operating system startup on GHF51-BN-43R15 causes the
 *      system hang in some cases. To minimize the window of interception and
 *      the need of dealing with proprietary firmware behaviour, we intercept
 *      APIC access only after the system transitioned to the bootloader.
 */
STATIC
VOID
EnableLocalApicIoInterceptIfNeeded (
    IN OUT HOST_CONTEXT* Context
    )
{
    //
    // Enable local APIC access interception if,
    //  - this is BSP,
    //  - the system is in the virtual mode (ie, in the bootloader before the OS),
    //  - the local APIC access interception has not started yet, and
    //  - there are more than one AP
    //
    if ((Context->Cpu->States.Guest.ProcessorNumber == 0) &&
        (EfiGoneVirtual() != FALSE) &&
        (g_LocalApicIoInterceptStarted == FALSE) &&
        (g_RemainingSipiCount != 0))
    {
        EnableLocalApicIoIntercept(Context->Cpu, TRUE);
        g_LocalApicIoInterceptStarted = TRUE;
        HOST_DEBUG((Context, "Started APIC intercepting\n"));
    }
}

/**
 * @brief Handles #VMEXIT.
 */
VOID
HandleVmExit (
    IN OUT HOST_VMEXIT_STACK* HostStack
    )
{
    HOST_CONTEXT context;

    //
    // Detect if stack has an unexpected value. This is a typical programming error.
    //
    HOST_ASSERT(HostStack->Params.Reserved1 == MAX_UINT32);

    //
    // Capture relevant information to handle #VMEXIT into the single structure.
    //
    context.Root = HostStack->Params.SharedContext;
    context.Cpu = &context.Root->Cpus[HostStack->Params.ProcessorNumber];
    context.Cpu->States.Guest.Registers = &HostStack->GuestRegisters;

    //
    // Reflect the guest RAX from VMCB to the register pointer. The following
    // VMLOAD is actually redundant and meaningless because this project does
    // not use registers updated by this instruction.
    //
    HostStack->GuestRegisters.Rax = context.Cpu->GuestVmcb.StateSaveArea.Rax;
    __svm_vmload((UINTN)&context.Cpu->HostVmcb);

    //
    // Previous #VMEXIT might set this field to flush TLB. Reset to zero to keep
    // TLB. Also, (re)enable caching of VMCB.
    //
    context.Cpu->GuestVmcb.ControlArea.TlbControl = 0;
    context.Cpu->GuestVmcb.ControlArea.VmcbClean = MAX_UINT32;

    //
    // Start intercepting access to local APIC if the conditions meet, so that
    // INIT-SIPI-SIPI is handled by the host.
    //
    EnableLocalApicIoInterceptIfNeeded(&context);

    //
    // Handle #VMEXIT.
    //
    switch (context.Cpu->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        HandleCpuid(&context);
        break;

    case VMEXIT_EXCEPTION_DB:
        HandleDebugException(&context);
        break;

    case VMEXIT_EXCEPTION_SX:
        HandleSecurityException(&context);
        break;

    case VMEXIT_NPF:
        HandleNestedPageFault(&context);
        break;

    default:
        HOST_DEBUG((&context,
                    "Unhandled #VMEXIT %016lx\n",
                    context.Cpu->GuestVmcb.ControlArea.ExitCode));
        HOST_ASSERT(FALSE);
        CpuReset();
    }

    //
    // Reflect back RAX to the VMCB in case the handler updated it.
    //
    context.Cpu->GuestVmcb.StateSaveArea.Rax = HostStack->GuestRegisters.Rax;
}

/**
 * @brief Handles exception occurred during execution of the host by simply
 *      halting the execution of the processor.
 */
VOID
HandleHostException (
    IN CONST HOST_EXCEPTION_STACK* Stack
    )
{
    HOST_DEBUG((NULL,
                "Unhandled host exception 0x%x at %p (%p)\n",
                (UINT8)Stack->InterruptNumber,
                Stack->Rip,
                Stack));
    HOST_ASSERT(FALSE);
    CpuReset();
}
