#ifndef NODE_H
#define NODE_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include <mpi.h>
#include <pthread.h>

#include "rbtree.h"

#define MASTER 0
#define RBTREE_FILENAME "rbtree.bin"

// * -----------------------------------------------------------------------------
// ---------------------------- fs_handle ----------------------------------------
// ----------------------------------------------------------------------------- *

typedef struct fs_handle {
  uint64_t num_blocks;
  uint64_t block_size;
  char *file_path;
  char **storage;
  rb_tree *t;
} fs_handle;

static uint32_t request_counter = 0;

FILE *acquire_file(uint64_t block_size);
fs_handle init_filesystem(uint64_t num_block, uint64_t block_size);
void free_handle(fs_handle handle);
char **malloc_blocks(int num_blocks, int block_size);

// * -----------------------------------------------------------------------------
// ---------------------------------- MPI ----------------------------------------
// ----------------------------------------------------------------------------- *
typedef struct {
  int op;
  size_t offset;
  size_t size;
  uint32_t req_id;
} mpi_request_t;

extern int rank;
extern int world_size;
extern char original_cwd[1024];

#define OP_READ 0
#define OP_WRITE 1

int handle_requests(fs_handle handle);
void read_chunk_from_row(uint64_t row, uint64_t offset, size_t size, char *buffer);
size_t block_id();

void send_read_request(uint64_t block, uint64_t offset, uint64_t size, char *buffer);
void send_write_request(uint64_t block, uint64_t offset, uint64_t size, const char *buffer);

// * -----------------------------------------------------------------------------
// ---------------------------- inode ----------------------------------------
// ----------------------------------------------------------------------------- *

#define ROOT_NODE 0

typedef struct inode {
  // file type/permissions
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;

  // timestamps
  uint32_t atime;
  uint32_t mtime;
  uint32_t ctime;

  // storage shape
  uint64_t ptr;
  uint64_t size;

  // pointer count
  uint32_t link_count;
} inode;

static const uint32_t FILETYPE_FILE = 0b001;
static const uint32_t FILETYPE_DIR  = 0b010;
static const uint32_t FILETYPE_ROOT = 0b100;

static const uint64_t HEADER_SIZE = 2*sizeof(uint64_t);

char *path_first(const char *path, char **rest);
char *path_last(const char *path, char **rest);
char **split_string(const char *s, char delim);
void remove_element(const char *buffer, size_t size, const char *str, char **out, size_t *out_size);

char **get_subdirectories(const char *buffer, uint64_t size, uint64_t **inode_numbers);

void write_inode(fs_handle handle, inode *node, uint64_t ptr);
inode *read_inode(fs_handle handle, uint64_t ptr);

bool inodes_equal(inode *node1, inode *node2);
void print_inode(inode *node);

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes

// Writes a block of data in storage starting at ptr
int write_chunk(fs_handle handle, uint64_t ptr, uint64_t size, const char *buffer);
int write_to_data(fs_handle, uint64_t ptr, uint64_t size, const char *buffer, uint64_t start);

// Reads a block of data in storage starting at ptr
int read_data_offset(fs_handle, uint64_t ptr, uint64_t size, char *buffer_ptr, uint64_t start);
int read_data(fs_handle handle, uint64_t ptr, uint64_t size, char *buffer);

uint64_t read_u64(const char *buffer);
void write_u64(char *buffer, uint64_t value);

char *read_inode_content(fs_handle handle, const inode *node);
void replace_inode_content(fs_handle handle, uint64_t node_ptr, const char *buffer, uint64_t size);

inode *create_inode(uint32_t uid, uint32_t gid, uint32_t mode, uint32_t size);

uint64_t get_tail_ptr(fs_handle handle, uint64_t ptr);
int append_to_inode(fs_handle handle, const char *buffer, uint64_t size, uint64_t node_ptr);
void add_child(fs_handle handle, const char *filename, uint64_t parent_ptr, uint64_t node_ptr);

uint64_t make_file(fs_handle handle, uint64_t parent_ptr, const char *name, const char *buffer, uint64_t size);
uint64_t make_directory(fs_handle handle, uint64_t parent_ptr, const char *name);

inode *find_inode(fs_handle handle, const char *path, uint64_t *node_ptr);

void free_chunks(fs_handle handle, uint64_t ptr);
int free_inode(fs_handle handle, uint64_t node_ptr);
int remove_directory(fs_handle handle, uint64_t node_ptr);
int remove_file(fs_handle handle, uint64_t node_ptr);

#endif
