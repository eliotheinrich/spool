#ifndef NODE_H
#define NODE_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "rbtree.h"

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

static const uint32_t BLOCK_SIZE = 102400;
static const uint32_t NUM_BLOCKS = 1;

static const uint64_t HEADER_SIZE = 2*sizeof(uint64_t);

char **init_filesystem(rb_tree **t);
char **malloc_blocks(int num_blocks, int block_size);

char *path_first(const char *path, const char **rest);
char *path_last(const char *path, const char **rest);
char **split_string(const char *s, char delim);
void remove_element(const char *data, size_t size, const char *str, char **out, size_t *out_size);

char **get_subdirectories(const char *data, uint64_t size, uint64_t **inode_numbers);

void write_inode(char **storage, inode *node, uint64_t ptr);
inode *read_inode(char **storage, uint64_t ptr);

bool inodes_equal(inode *node1, inode *node2);
void print_inode(inode *node);

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes

// Stores a block of data in storage starting at ptr
int write_chunk(char **storage, uint64_t ptr, uint64_t size, const char *data);
int write_to_chunk(char **storage, uint64_t ptr, uint64_t size, const char *data, uint64_t start);
// Reads a block of data in storage starting at ptr
int read_data_offset(const char **storage, uint64_t ptr, uint64_t size, char *data_ptr, uint64_t start);
int read_data(const char **storage, uint64_t ptr, uint64_t size, char *data);

uint64_t read_u64(const char *data);
void write_u64(char *data, uint64_t value);

char *read_inode_content(const char **storage, const inode *node);
void replace_inode_content(char **storage, rb_tree *t, uint64_t node_ptr, const char *data, uint64_t size);

inode *create_inode(uint32_t uid, uint32_t gid, uint32_t mode, uint32_t size);

uint64_t get_tail_ptr(const char **storage, uint64_t ptr);
int append_to_inode(rb_tree *t, char **storage, const char *data, uint64_t size, uint64_t node_ptr);
void add_child(rb_tree *t, char **storage, const char *filename, uint64_t parent_ptr, uint64_t node_ptr);

uint64_t make_file(rb_tree *t, char **storage, uint64_t parent_ptr, const char *name, const char *data, uint64_t size);
uint64_t make_directory(rb_tree *t, char **storage, uint64_t parent_ptr, const char *name);

inode *find_inode(const char **storage, const char *path, uint64_t *node_ptr);

void free_chunks(char **storage, rb_tree *t, uint64_t ptr);
int free_inode(char **storage, rb_tree *t, uint64_t node_ptr);
int remove_directory(char **storage, rb_tree *t, uint64_t node_ptr);
int remove_file(char **storage, rb_tree *t, uint64_t node_ptr);

#endif
