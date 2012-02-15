OBJS = synfrag.o checksums.o
SRCS = $(OBJS,.o=.c)
CFLAGS += -Wall

all: synfrag

synfrag.o: synfrag.c
	$(CC) $(CFLAGS) -c -o $@ synfrag.c

checksums.o: checksums.c
	$(CC) $(CFLAGS) -c -o $@ checksums.c

synfrag: $(OBJS)
	$(CC) $(LDFLAGS) -lpcap -o synfrag $(OBJS)

clean:
	rm -rf *.o synfrag

