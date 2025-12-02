#ifndef NODE_H
#define NODE_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

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
  uint32_t size;

  // pointer count
  uint32_t link_count;
} inode;

static const uint32_t FILETYPE_FILE = 0b01;
static const uint32_t FILETYPE_DIR  = 0b10;
static const uint32_t FILETYPE_MASK = 0b11;

static const uint32_t BLOCK_SIZE = 1024;
static const uint32_t NUM_BLOCKS = 100;

// Returns the root portion of the path
void split_root(const char* path, char** first, char** rest);
// Returns the child portion of the path
void split_parent(const char *path, char **parent_out, char **name_out);

char **split_string(const char *s, char delim);

inode *create_file(uint32_t uid, uint32_t gid, uint32_t size);

void write_inode(inode *node, int inode_number, char **metadata);
void read_inode(inode *node, int inode_number, char **metadata);

bool inodes_equal(inode *node1, inode *node2);
void print_inode(inode *node);

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes

// Stores a block of data in storage starting at ptr
int write_data(uint64_t ptr, char *data, uint32_t size, char **storage);
int write_inode_data(inode *node, char *data, char **storage);

int read_data(uint64_t ptr, char **data_ptr, uint32_t size, char **storage);
int read_inode_data(inode *node, char **data_ptr, char **storage);

char **malloc_blocks(int num_blocks, int block_size);

void write_inode_metadata(inode *node, char *data, char **metadata);
char *read_inode_metadata(inode *node, char **metadata);

//char *write_tree(const Node *root, size_t *out_size);
//Node *read_tree(const char *buffer);
//bool trees_equal(const Node* r1, const Node* r2);
//Node *make_root();
//Node *load_filesystem(int backing_fd);
//Node *create_node(const char *name, const char *content, NodeType type);
//void print_tree(const Node *root);
//Node *find_node(Node *node, const char *path);
//void add_child(Node *root, Node *node);
//void free_tree(Node *node);

#endif
