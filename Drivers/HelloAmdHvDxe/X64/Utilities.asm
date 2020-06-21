;
; @file Utilities.asm
;
; @brief Utility functions.
;
; @author Satoshi Tanda
;
; @copyright Copyright (c) 2017-2019, Satoshi Tanda. All rights reserved.
;
.code

;
; @brief Returns the return address from this function.
;
; @return The return address from this function.
;
AsmReadInstructionPointer proc
        mov     rax, [rsp]
        ret
AsmReadInstructionPointer endp

;
; @brief Returns the current value of RSP.
;
; @return The current value of RSP.
;
AsmReadStackPointer proc
        mov     rax, rsp
        add     rax, 8
        ret
AsmReadStackPointer endp

        end
