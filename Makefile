CC = gcc
CFLAGS = -Wall -Wextra -I.
LDFLAGS = -lpcap
TARGET = sniffer

SRC_DIR = .
UTIL_DIR = util
PRINT_DIR = display

SOURCES = $(SRC_DIR)/main.c $(UTIL_DIR)/util.c $(PRINT_DIR)/print.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(UTIL_DIR)/%.o: $(UTIL_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(PRINT_DIR)/%.o: $(PRINT_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: all clean
