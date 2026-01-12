# Makefile for cbindings_chat_tui C example

CC = gcc
CFLAGS = -Wall -Wextra -I../../library -pthread
LDFLAGS = -L../../build -lchat -lncurses -Wl,-rpath,../../build

BUILD_DIR = ../../build
TARGET = $(BUILD_DIR)/cbindings_chat_tui
SRC = cbindings_chat_tui.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

# Run with default settings
run: $(TARGET)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(TARGET)

# Run as alice on port 60001
run_alice: $(TARGET)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(TARGET) --name=Alice --port=60001

# Run as bob on port 60002
run_bob: $(TARGET)
	LD_LIBRARY_PATH=$(BUILD_DIR) $(TARGET) --name=Bob --port=60002

help:
	@echo "Usage:"
	@echo "  make            - Build cbindings_chat_tui"
	@echo "  make run        - Build and run with defaults"
	@echo "  make run_alice  - Build and run as Alice on port 60001"
	@echo "  make run_bob    - Build and run as Bob on port 60002"
	@echo "  make clean      - Remove built files"
