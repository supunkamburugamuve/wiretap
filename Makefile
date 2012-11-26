CC=gcc -pthread

CFLAGS=-c -Wall

all: wiretap

wiretap: wiretap.o list.o
	$(CC) wiretap.o list.o -o wiretap -lpcap

wiretap.o: wiretap.c
	$(CC) $(CFLAGS) wiretap.c

list.o: list.c
	$(CC) $(CFLAGS) list.c

clean:
	rm -rf *.o wiretap 
