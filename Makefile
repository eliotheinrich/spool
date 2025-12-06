CC = mpicc

SRC_DIR = src
TEST_DIR = src/tests
MPI_DIR = /usr/include/mpich-aarch64/
MPI_LIB = /usr/lib64/mpich/lib/

CFLAGS = -Wall -g -D_FILE_OFFSET_BITS=64 -I$(SRC_DIR) -I$(MPI_DIR) -L$(MPI_LIB) -lmpi -DMPI
FUSE_FLAGS = $(shell pkg-config fuse3 --cflags --libs)

MAIN_SRC = $(SRC_DIR)/main.c
RBTREE_SRC = $(SRC_DIR)/rbtree.c
NODE_SRC = $(SRC_DIR)/node.c
TEST_SRC = $(TEST_DIR)/tests.c


MAIN_OBJ = $(MAIN_SRC:.c=.o) $(RBTREE_SRC:.c=.o) $(NODE_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o) $(RBTREE_SRC:.c=.o) $(NODE_SRC:.c=.o)

.PHONY: all clean

all: main tests

main: $(MAIN_OBJ)
	$(CC) $(CFLAGS) $(MAIN_OBJ) $(FUSE_FLAGS) -o $@

tests: $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) $(FUSE_FLAGS) -o $@

# Compile .c → .o
%.o: %.c
	$(CC) $(CFLAGS) $(FUSE_FLAGS) -c $< -o $@

clean:
	rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o main tests

