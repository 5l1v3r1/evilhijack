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

BITS 64

push rbp
mov rbp, rsp

;;;;;;;;;;;;;;;;;;;;
; Backup registers ;
;;;;;;;;;;;;;;;;;;;;

push rdi
push rsi
push rdx
push rcx
push rbx
push rax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Call sandbox_freebsd_open ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

mov rdi, 0x1111111111111111 ; .so filename (string)
xor rsi, rsi
xor rdx, rdx
xor rcx, rcx
mov rax, 0x00000000011cade0 ; sandbox_freebsd_open
call rax

;;;;;;;;;;;;;;;
; Call fdlopen ;
;;;;;;;;;;;;;;;

mov rdi, rax
mov rsi, 0x102
mov rax, 0x2222222222222222 ; addr of fdlopen (unsigned long)
call rax

;;;;;;;;;;;;;;
; Call dlsym ;
;;;;;;;;;;;;;;

mov rdi, rax
mov rsi, 0x3333333333333333 ; function name (string)
mov rax, 0x4444444444444444 ; addr of dlsym (unsigned long)
call rax
push rax

;;;;;;;;;;;;;;;;;;;;;;;;;
; Mark PLT/GOT writable ;
;;;;;;;;;;;;;;;;;;;;;;;;;
mov rbx, 0x5555555555555555 ; addr of PLT/GOT entry (unsigned long)
push rbx
mov rax, 74
mov rdi, rbx
and rdi, 0xfffffffffffff000
mov rsi, 4096
mov rdx, 0x7
syscall

;;;;;;;;;;;;;;;;;
; Patch PLT/GOT ;
;;;;;;;;;;;;;;;;;

pop rbx
pop rax
mov [rbx], rax

;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Mark PLT/GOT unwritable ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;
mov rdi, rbx
and rdi, 0xfffffffffffff000
mov rax, 74
mov rsi, 4096
mov rdx, 0x5
syscall

;;;;;;;;;;;;;;;;;;;;;
; Restore registers ;
;;;;;;;;;;;;;;;;;;;;;

pop rax
pop rbx
pop rcx
pop rdx
pop rsi
pop rdi
pop rbp

ret
