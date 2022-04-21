# IPK Projekt 2 (Varianta ZETA: Sniffer paketů)

## Stručný popis programu
Cieľom projektu bolo vytvoriť program, ktorý slúži na analýzu sieťovej prevádzky na sieti. Program je implementovaný v jazyku C. Po preložení a spustení programu s platnými atribútmi program pristupuje k analýze sieťovej prevádzky. Používateľ má možnosť zvoliť typ paketov, ktoré chce zachytávať ale aj rozhranie, na ktorom má program odpočúvať komunikáciu. Pokiaľ používateľ zvolí neplatnú konfiguráciu filtrov, nedôjde k ukončeniu činnosti programu. Analyzátor bude spracúvať a odpočúvať komunikáciu akéhokoľvek druhu.

## Build
Pred prvotným spustením programu je nutné vykonať preloženie bináriek príkazom make.
```bash
make
```

## Princíp spustenia programu
```bash
./ipk-sniffer [-i rozhranie | --interface rozhranie] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```

## Ukázkový príklad spustenia programu

Príkaz :
```bash
./ipk-sniffer -i en0 --tcp --udp -p 443
```
Výstup programu:

```
timestamp : 2022-04-21T13:00:56.399+02:00
src MAC : a0:78:17:8f:0f:0a 
dst MAC : dc:ef:80:56:4b:8e 
frame length : 108 bytes
src IP : 147.229.183.218
dst IP : 162.159.135.234
src port : 57364
dst port : 443
0x0000: dc ef 80 56 4b 8e a0 78  17 8f 0f 0a 08 00 45 00  ...VK..x......E.
0x0010: 00 5e 00 00 40 00 40 06  c4 50 93 e5 b7 da a2 9f  .^..@.@..P......
0x0020: 87 ea e0 14 01 bb 8e a6  60 39 03 b4 65 d1 50 18  ........`9..e.P.
0x0030: 10 00 19 36 00 00 17 03  03 00 31 a9 ad 0f 54 1f  ...6......1...T.
0x0040: 81 c5 d4 64 d0 6e 61 1b  27 1e 98 5b d8 3e 65 0e  ...d.na.'..[.>e.
0x0050: 61 bd 8c f6 db 47 98 c5  15 58 03 0c 1f e5 ba d1  a....G...X......
0x0060: a4 ea 7f 2e 14 f7 4f c3  a4 e9 80 f1              ......O.....
```

## Zoznam odovzdaných súborov

* sniffer.c
* sniffer.h
* Makefile
* README.md
* manual.pdf
