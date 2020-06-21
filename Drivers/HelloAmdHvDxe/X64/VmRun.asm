;
; @file VmRun.asm
;
; @brief The VMRUN loop.
;
; @author Satoshi Tanda
;
; @copyright Copyright (c) 2017-2019, Satoshi Tanda. All rights reserved.
;
include Macros.inc

.code

extern HandleVmExit : proc

;
; @brief Enters the loop that executes the guest and handles #VMEXIT.
;
; @details This function switchs to the host stack pointer, runs the guest
;   and handles #VMEXIT indefinitely. This project does not implement
;   de-virtualization.
;
; @param[in] HostRsp - A stack pointer for the hypervisor.
;
AsmLaunchVm proc
        ;
        ; Update the current stack pointer with the host RSP. This protects
        ; values stored on stack for the hypervisor from being overwritten by
        ; the guest due to a use of the same stack memory.
        ;
        mov     rsp, rcx        ; Rsp <= HostRsp (== &GuestVmcbPa)

AsLV10: ;
        ; Run the loop to executed the guest and handle #VMEXIT.
        ;
        mov     rax, [rsp]      ; RAX <= GuestVmcbPa
        vmload  rax             ; load previously saved guest state from VMCB

        ;
        ; Start the guest. The VMRUN instruction resumes execution of the guest
        ; with state described in VMCB (specified by RAX by its physical address)
        ; until #VMEXI is triggered. On #VMEXIT, the VMRUN instruction completes
        ; and resumes the next instruction (ie, vmsave in our case).
        ;
        ; The VMRUN instruction does the following things in this order:
        ; - saves some current state (ie. host state) into the host state-save
        ;   area specified in IA32_MSR_VM_HSAVE_PA
        ; - loads guest state from the VMCB state-save area
        ; - enables interrupts by setting the the global interrupt flag (GIF)
        ; - resumes execution of the guest until #VMEXIT occurs
        ; See "Basic Operation" for more details.
        ;
        ; On #VMEXIT:
        ; - disables interrupts by clearing the the global interrupt flag (GIF)
        ; - saves current guest state into and update VMCB to provide information
        ;   to handle #VMEXIT
        ; - loads the host state previously saved by the VMRUN instruction
        ; See "#VMEXIT" in the volume 2 and "VMRUN" in the volume 3 for more
        ; details.
        ;
        vmrun   rax             ; Switch to the guest until #VMEXIT

        ;
        ; #VMEXIT occured. Now, some of guest state has been saved to VMCB, but
        ; not all of it. Save some of unsaved state with the VMSAVE instruction.
        ;
        ; RAX (and some other state like RSP) has been restored from the host
        ; state-save, so it has the same value as before and not guest's one.
        ;
        vmsave  rax             ; Save current guest state to VMCB

        ;
        ; Also save guest's GPRs and XMM registers since those are not saved
        ; anywhere by the processor on #VMEXIT and will (may) be destroyed by
        ; subsequent host code. Before saving XMM registers, RSP is aligned to
        ; 16 bytes to avoid exception.
        ;
        PUSH_GPRS
        mov     rcx, rsp        ; Save the current RSP as a parameter of HandleVmExit
        mov     r15, rsp        ; Save the current RSP to restore later
        and     rsp, 0fffffffffffffff0h         ; Align RSP with 16 bytes
        PUSH_XMM

        ;
        ; Handle #VMEXIT.
        ;
        sub     rsp, 20h
        call    HandleVmExit
        add     rsp, 20h

        ;
        ; Restore XMM and GPRs, and continue execution of the guest.
        ;
        POP_XMM
        mov     rsp, r15        ; Restore RSP to the pre-16-byte-aligned value
        POP_GPRS
        jmp     AsLV10

AsmLaunchVm endp

        end
