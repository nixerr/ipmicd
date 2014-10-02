ipmicd
======

tools for ping ipmi and dump hashes


Compile under Linux:
gcc ipmicd.c -static -o ipmicd

Compile under Windows(use MinGW):
gcc ipmicd.c -mno-ms-bitfields -lws2_32 -DMINGW
