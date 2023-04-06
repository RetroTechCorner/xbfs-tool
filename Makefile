CC=gcc
CFLAGS=-I.
DEPS = xbfs.h sha256.h 
OBJ = utils.o xbfs-tool.o sha256.o xbfs-insert.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

xbfs-tool: utils.o xbfs-tool.o sha256.o
	$(CC) -o $@ utils.o xbfs-tool.o sha256.o $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~ core xbfs-tool xbfs-insert 