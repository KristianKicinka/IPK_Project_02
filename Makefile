CC=gcc
CFLAGS=-Wall -std=gnu99 -ggdb3 -lpcap
FILES= sniffer.c

.PHONY: ipk-sniffer clean

all:ipk-sniffer

ipk-sniffer: $(FILES)
	$(CC) $(CFLAGS) -o $@ $(FILES) -lm -lpcap

clean:
	@rm -f ipk-sniffer