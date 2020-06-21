;
; @file Macros.inc
;
; @brief Macros for assembly code.
;
; @author Satoshi Tanda
;
; @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
;

;
; @brief Saves all general purpose registers to the stack.
;
; @details This macro does not alter the flag register.
;
PUSH_GPRS macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;
; @brief Saves all XMM registers to the stack.
;
PUSH_XMM macro
        sub     rsp, 60h
        movaps  xmmword ptr [rsp +  0h], xmm0
        movaps  xmmword ptr [rsp + 10h], xmm1
        movaps  xmmword ptr [rsp + 20h], xmm2
        movaps  xmmword ptr [rsp + 30h], xmm3
        movaps  xmmword ptr [rsp + 40h], xmm4
        movaps  xmmword ptr [rsp + 50h], xmm5
        endm

;
; @brief Loads all general purpose registers from the stack.
;
; @details This macro does not alter the flag register.
;
POP_GPRS macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;
; @brief Loads all XMM registers from the stack.
;
POP_XMM macro
        movaps  xmm5, xmmword ptr [rsp + 50h]
        movaps  xmm4, xmmword ptr [rsp + 40h]
        movaps  xmm3, xmmword ptr [rsp + 30h]
        movaps  xmm2, xmmword ptr [rsp + 20h]
        movaps  xmm1, xmmword ptr [rsp + 10h]
        movaps  xmm0, xmmword ptr [rsp +  0h]
        add     rsp, 60h
        endm
