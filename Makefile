all: honeypot
honeypot:honeypot.c sqlite3.o
	$(CC) -o $@ cJSON.c $< sqlite3.o -lm -lpthread -ldl -lcurl -lpcap -std=gnu11 `pkg-config --cflags --libs libpjproject`
sqlite3.o:sqlite3.c
	gcc -o sqlite3.o -c sqlite3.c
clean:
	rm -f honeypot.o honeypot
