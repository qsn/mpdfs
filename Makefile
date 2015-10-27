CFLAGS=`pkg-config fuse libmpdclient --cflags`
LDFLAGS=`pkg-config fuse libmpdclient libbsd --libs`

SOURCES=mpdfs.c lib.c
OBJECTS=$(SOURCES:.c=.o)

all: mpdfs

mpdfs: $(OBJECTS)

clean:
	rm -f $(OBJECTS) *\~
