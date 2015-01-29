
.PHONY=all
all: ipmicd

ipmicd: ipmicd.c
	gcc -Wall -O3 -o ipmicd ipmicd.c
