/**
 * @file HelloAmdHv.h
 *
 * @brief The header to be included from all complation units (global definitions).
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/LocalApicLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MtrrLib.h>
#include <Library/PrintLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/MpService.h>
#include <Register/Amd/Cpuid.h>
#include <Register/Amd/Msr.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/LocalApic.h>
#include "Svm.h"

//
// MSVC intrinsics.
//
VOID __svm_clgi(VOID);
VOID __svm_invlpga(IN VOID* VirtualAddress, IN UINT32 Asid);
VOID __svm_skinit(IN UINT32 SlbPhysicalAddress);
VOID __svm_stgi(VOID);
VOID __svm_vmload(IN UINTN VmcbPhysicalAddress);
VOID __svm_vmrun(IN UINTN VmcbPhysicalAddress);
VOID __svm_vmsave(IN UINTN VmcbPhysicalAddress);
unsigned long __segmentlimit(IN unsigned long SegmentSelector);

//
// General architectural CPUID and MSR(s).
//
#define EFER_SVME                                   (1UL << 12)
#define CPUID_SVM_FEATURES                          0x8000000a
#define CPUID_SVM_FEATURES_EDX_NP                   BIT0
#define CPUID_EXTENDED_CPU_SIG_ECX_SVM              BIT2
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)

//
// Hyper-V Hypervisor Top-Level Functional Specification (TLFS) related.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   ((UINT32)0x40000000)
#define CPUID_HV_INTERFACE                  ((UINT32)0x40000001)
#define CPUID_HV_MAX                        CPUID_HV_INTERFACE

//
// The entry count in the single paging structure table.
//
#define PAGE_TABLE_ENTRY_COUNT     512

//
// The helper union to split the 64bit value into indexes used to select page
// table entries.
//
typedef union _ADDRESS_TRANSLATION_HELPER
{
    struct
    {
        UINT64 Unused : 12;         //< [11:0]
        UINT64 Pt : 9;              //< [20:12]
        UINT64 Pd : 9;              //< [29:21]
        UINT64 Pdpt : 9;            //< [38:30]
        UINT64 Pml4 : 9;            //< [47:39]
    } AsIndex;
    UINT64 AsUInt64;
} ADDRESS_TRANSLATION_HELPER;

//
// See "2-Mbyte PML4E-Long Mode" and "2-Mbyte PDPE-Long Mode".
//
typedef union _PML4_ENTRY_2MB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Reserved1 : 3;           // [6:8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PML4_ENTRY_2MB, *PPML4_ENTRY_2MB,
  PDP_ENTRY_2MB, *PPDP_ENTRY_2MB;
STATIC_ASSERT(sizeof(PML4_ENTRY_2MB) == 8, "PML4_ENTRY_1GB Size Mismatch");

//
// See "2-Mbyte PDE-Long Mode".
//
typedef union _PD_ENTRY_2MB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 LargePage : 1;           // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 Pat : 1;                 // [12]
        UINT64 Reserved1 : 8;           // [13:20]
        UINT64 PageFrameNumber : 31;    // [21:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PD_ENTRY_2MB, *PPD_ENTRY_2MB;
STATIC_ASSERT(sizeof(PD_ENTRY_2MB) == 8, "PDE_ENTRY_2MB Size Mismatch");

//
// See "4-Kbyte PTE—Long Mode".
//
typedef union _PT_ENTRY_4KB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 Pat : 1;                 // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PT_ENTRY_4KB;
STATIC_ASSERT(sizeof(PT_ENTRY_4KB) == 8, "PT_ENTRY_4KB Size Mismatch");

typedef struct _PAGING_STRUCTURES
{
    PML4_ENTRY_2MB Pml4[PAGE_TABLE_ENTRY_COUNT];
    PDP_ENTRY_2MB Pdpt[1][PAGE_TABLE_ENTRY_COUNT];
    PD_ENTRY_2MB Pd[1][PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} PAGING_STRUCTURES;
STATIC_ASSERT((OFFSET_OF(PAGING_STRUCTURES, Pdpt) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PAGING_STRUCTURES, Pd) % SIZE_4KB) == 0, "Must be 4KB aligned");

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
// The layout of the variables stored in the host stack.
//
typedef struct _HOST_STACK_BASED_PARAMETERS
{
    UINT64 GuestVmcbPa;
    struct _ROOT_CONTEXT* SharedContext;
    UINT32 ProcessorNumber;
    UINT32 Reserved1;
} HOST_STACK_BASED_PARAMETERS;

//
// The layout of the whole host stack where the size is defined by HOST_STACK_SIZE.
//
#define HOST_STACK_SIZE   SIZE_8KB
typedef union _HOST_STACK
{
    //
    //  Low     HostStackLimit[0]                      StackLimit
    //  ^       ...
    //  ^       HostStackLimit[HOST_STACK_SIZE - 2]    StackBase
    //  High    HostStackLimit[HOST_STACK_SIZE - 1]    StackBase
    //
    UINT8 HostStackLimit[HOST_STACK_SIZE];
    struct
    {
        //
        // Available for the hypervisor to freely use.
        //
        UINT8 AvailableAsStack[HOST_STACK_SIZE - sizeof(HOST_STACK_BASED_PARAMETERS)];

        //
        // Set up by the kernel-mode code before starting the hypervisor.
        // The hypervisor never overwrites this contents.
        //
        HOST_STACK_BASED_PARAMETERS Params;
    } Layout;
} HOST_STACK;
STATIC_ASSERT(sizeof(HOST_STACK) == HOST_STACK_SIZE, "Must be 4KB aligned");

//
// Guest General Purpose Registers (GPRs) created on VM-exit from the guest
// state and write back to the guest on VM-entry.
//
typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS;

//
// Collection of book keeping state variables the virtual processor.
//
typedef enum _GUEST_ACTIVITY_STATE
{
    GuestStateActive,
    GuestStateWaitForSipi,
    GuestStateSipiIssued,
} GUEST_ACTIVITY_STATE;

typedef enum _APIC_ACCESS_STATE
{
    ApicAccessPassthrough,
    ApicAccessPending,
} APIC_ACCESS_STATE;

typedef struct _GUEST_STATE
{
    UINT32 ProcessorNumber;
    UINT32 ApicId;
    volatile GUEST_ACTIVITY_STATE ActivityState;
    APIC_ACCESS_STATE ApicAccessState;
    GUEST_REGISTERS* Registers;
    UINT8 SipiVector;
    BOOLEAN DisgardInitSignal;
} GUEST_STATE;

typedef struct _SVM_STATE
{
    PT_ENTRY_4KB* LocalApicNestedPte;
} SVM_STATE;

typedef struct _CONTEXT_COLLECTION
{
    GUEST_STATE Guest;
    SVM_STATE Svm;
    UINT8 Reserved1[SIZE_4KB - sizeof(GUEST_STATE) - sizeof(SVM_STATE)];
} CONTEXT_COLLECTION;
STATIC_ASSERT((sizeof(CONTEXT_COLLECTION) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// The entry count within the IDT.
//
#define IDT_ENTRY_COUNT     256

//
// Data structures used for host execution environemnt across all processors.
//
typedef struct _SHARED_HOST_DATA
{
    PAGING_STRUCTURES PagingStructures;
    IA32_IDT_GATE_DESCRIPTOR Idt[IDT_ENTRY_COUNT];
    IA32_DESCRIPTOR Idtr;
    UINT8 Reserved2[2];
    UINT32 ProcessorCount;
    UINT64 Cr3;
    UINT8 Reserved1[SIZE_4KB - sizeof(IA32_DESCRIPTOR) - sizeof(UINT8[2]) - sizeof(UINT32) - sizeof(UINT64)];
} SHARED_HOST_DATA;
STATIC_ASSERT((sizeof(SHARED_HOST_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_HOST_DATA, Idt) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Data structures used for host execution environemnt for each processor.
//
typedef struct _HOST_DATA
{
    CONST SHARED_HOST_DATA* Shared;
    IA32_SEGMENT_DESCRIPTOR Gdt[16];
    IA32_DESCRIPTOR Gdtr;
    IA32_TASK_STATE_SEGMENT Tss;
    UINT8 Reserved1[SIZE_4KB - sizeof(SHARED_HOST_DATA*) - sizeof(IA32_SEGMENT_DESCRIPTOR) * 16 - sizeof(IA32_DESCRIPTOR) - sizeof(IA32_TASK_STATE_SEGMENT)];
} HOST_DATA;
STATIC_ASSERT((sizeof(HOST_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// The collection of data structures allocated for each processors.
//
typedef struct _PER_CPU_DATA
{
    MEMORY_LOGS Logs;
    CONTEXT_COLLECTION States;

    VMCB GuestVmcb;
    VMCB HostVmcb;
    HOST_STACK HostStack;
    UINT8 HostStateArea[SIZE_4KB];
    HOST_DATA HostX64Data;
} PER_CPU_DATA;
STATIC_ASSERT((sizeof(PER_CPU_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, GuestVmcb) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostVmcb) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostStack) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostStateArea) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Data structures related to SVM and used for all processors.
//
typedef struct _SHARED_SVM_DATA
{
    PAGING_STRUCTURES NestedPageTables;
    PAGING_STRUCTURES NestedPageTablesForBsp;
    PT_ENTRY_4KB NestedPtForBsp[PAGE_TABLE_ENTRY_COUNT];
    UINT8 ShadowLocalApicPage[SIZE_4KB];
} SHARED_SVM_DATA;
STATIC_ASSERT((sizeof(SHARED_SVM_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, NestedPageTablesForBsp) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, NestedPtForBsp) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, ShadowLocalApicPage) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// This is the structure that is holds all information for the entire hypervisor
// and virtual processors. This is allocated at the runtime-memory only once and
// made up of per-PER_CPU_DATA,
//
typedef struct _ROOT_CONTEXT
{
    SHARED_SVM_DATA Svm;
    SHARED_HOST_DATA HostX64;
    PER_CPU_DATA Cpus[0];
} ROOT_CONTEXT;
STATIC_ASSERT((sizeof(ROOT_CONTEXT) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(ROOT_CONTEXT, HostX64) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(ROOT_CONTEXT, Cpus) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// The collection of data structures to handle #VMEXIT.
//
typedef struct _HOST_CONTEXT
{
    PER_CPU_DATA* Cpu;
    ROOT_CONTEXT* Root;
} HOST_CONTEXT;

//
// The remaining count to stop local APIC access interception.
//
extern volatile UINT32 g_RemainingSipiCount;

//
// The physical address of the ResetSystem runtime service.
//
extern EFI_RESET_SYSTEM g_ResetSystemPhys;

//
// Log buffer used when the host context is not specified.
//
extern MEMORY_LOGS* g_GlobalLogBuffer;
