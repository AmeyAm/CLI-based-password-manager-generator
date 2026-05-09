CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic
LDLIBS ?= -lcrypto

TARGET = password_manager
SRC = main.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) main *.o
