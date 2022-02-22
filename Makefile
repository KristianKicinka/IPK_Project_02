CC=gcc
CFLAGS=-Wall -std=c11 -pedantic -lm -ggdb3 -g
FILES= sniffer.c

.PHONY: ipk-sniffer clean

all:ipk-sniffer

ipk-sniffer: $(FILES)
	$(CC) $(CFLAGS) -o $@ $(FILES)

clean:
	@rm -f ipk-sniffer