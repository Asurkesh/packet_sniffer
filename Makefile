CC=gcc
CFLAGS=-Wall
LIBS=-lpcap
TARGET=sniffer

all: $(TARGET)

$(TARGET): main.c
	$(CC) main.c -o $(TARGET) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
