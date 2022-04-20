CC=gcc
CFLAGS=-Wall -std=c11 -pedantic -ggdb3 -g
FILES= sniffer.c

.PHONY: ipk-sniffer clean

all:ipk-sniffer

ipk-sniffer: $(FILES)
	$(CC) $(CFLAGS) -o $@ $(FILES) -lm -lpcap

clean:
	@rm -f ipk-sniffer