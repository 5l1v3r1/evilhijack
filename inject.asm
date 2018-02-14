;- Copyright (c) 2018, Shawn Webb
; All rights reserved.
; 
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions
; are met:
; 
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above
;      copyright notice, this list of conditions and the following
;      disclaimer in the documentation and/or other materials
;      provided with the distribution.
; 
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
; COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
; INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
; STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
; OF THE POSSIBILITY OF SUCH DAMAGE.

; XXX NOTE:
; Some addresses below are hardcoded to match my FreeBSD 12-CURRENT
; system. These addresses should be updated for 11.1-RELEASE before
; CarolinaCon and Thotcon.

BITS 64

;;;;;;;;;;;;;;;;;;;;
; Backup registers ;
;;;;;;;;;;;;;;;;;;;;

push rbp
mov rbp, rsp

push rax
push rbx
push rsi
push rdi
push rdx

;;;;;;;;;;;;;;;
; Call dlopen ;
;;;;;;;;;;;;;;;

mov rdi, 0x1111111111111111 ; .so filename (string)
mov rsi, 0x102
mov rbx, 0x80060c070 ; addr of dlopen (unsigned long)
call rbx

;;;;;;;;;;;;;;
; Call dlsym ;
;;;;;;;;;;;;;;

mov rdi, rax
mov rsi, 0x2222222222222222 ; function name (string)
mov rbx, 0x80060c230 ; addr of dlsym (unsigned long)
call rbx

;;;;;;;;;;;;;;;;;
; Patch PLT/GOT ;
;;;;;;;;;;;;;;;;;

mov rbx, 0x3333333333333333 ; addr of PLT/GOT entry (unsigned long)
mov [rbx], rax

;;;;;;;;;;;;;;;;;;;;;
; Restore registers ;
;;;;;;;;;;;;;;;;;;;;;

pop rdx
pop rdi
pop rsi
pop rbx
pop rax

pop rbp

ret
