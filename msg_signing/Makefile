CC=gcc
CFLAGS= -Wall -I.
SOURCES=main.c uglylogging.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=publisher
LDFLAGS=-lc -lcrypto -lmosquitto

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@ 

clean:
	rm -rf $(OBJECTS)
	rm -rf $(EXECUTABLE)
