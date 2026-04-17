CC = gcc

PG_INC = $(shell pg_config --includedir)

CFLAGS = -Wall -Wextra -Isrc/includes -I$(PG_INC) -O2 \
         -DHAVE_LIBPQ -DHAVE_OPENSSL -DHAVE_ARGON2 -DHAVE_MONGOOSE \
         -DMG_TLS=MG_TLS_OPENSSL

LDFLAGS = -lssl -lcrypto -lpq -largon2 -lpthread

SRC_DIR = src
OBJ_DIR = obj

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = securevault_web

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean
