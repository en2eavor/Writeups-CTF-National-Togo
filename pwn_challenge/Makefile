# Makefile for PWN Challenge

CC = gcc
CFLAGS = -fno-stack-protector -z execstack -no-pie -g
TARGET = guess_game

# Default target
all: $(TARGET)

$(TARGET): guess_game.c
	$(CC) $(CFLAGS) -o $(TARGET) guess_game.c
	@echo "Compilation successful!"
	@echo "Binary created: $(TARGET)"
	@echo ""
	@echo "Vulnerabilities enabled:"
	@echo "  - No stack protection (-fno-stack-protector)"
	@echo "  - Executable stack (-z execstack)"
	@echo "  - No PIE (-no-pie)"

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
