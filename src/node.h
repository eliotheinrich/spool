#ifndef NODE_H
#define NODE_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include <mpi.h>
#include <pthread.h>

#include "thread_pool.h"
#include "rbtree.h"

#define MASTER 0
#define RBTREE_FILENAME "rbtree.bin"

// * -----------------------------------------------------------------------------
// ---------------------------- fs_handle *----------------------------------------
// ----------------------------------------------------------------------------- *

typedef struct {
  uint64_t num_drives;
  uint64_t drive_size;
  int raid_level;
  uint16_t stripe_size;
  uint64_t fs_size;
  char *file_path;
  char **storage;
  rb_tree *t;
  thread_pool *pool;
} fs_handle;

static uint32_t request_counter = 0;

char *init_file(char *filename, uint64_t drive_size);
char *acquire_file(char *filename, uint64_t drive_size);
fs_handle *acquire_filesystem(uint64_t num_drives, uint64_t drive_size, int raid_level);
fs_handle *init_filesystem(uint64_t num_drives, uint64_t drive_size, int raid_level);
void free_handle(fs_handle *handle);
char **malloc_blocks(int num_drives, int drive_size);

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
#define OP_WAIT 2

int handle_requests(fs_handle *handle);
void send_read_request(uint64_t device, uint64_t offset, uint64_t size, char *buffer);
void send_write_request(uint64_t device, uint64_t offset, uint64_t size, const char *buffer);

// * -----------------------------------------------------------------------------
// ---------------------------- inode ----------------------------------------
// ----------------------------------------------------------------------------- *

#define ROOT_NODE 0

typedef struct {
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

void set_timestamp(inode *node, const struct timespec tv[2]);
char *path_first(const char *path, char **rest);
char *path_last(const char *path, char **rest);
char **split_string(const char *s, char delim);
void remove_element(const char *buffer, size_t size, const char *str, char **out, size_t *out_size);

char **get_subdirectories(const char *buffer, uint64_t buffer_size, uint64_t **inode_numbers);

void print_directory_content(char *content, uint64_t content_size);

void write_inode(fs_handle *handle, inode *node, uint64_t ptr);
inode *read_inode(fs_handle *handle, uint64_t ptr);

bool inodes_equal(inode *node1, inode *node2);
void print_inode(inode *node);

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each device, P is the pointer to the next device, and D is the bytes

// Writes a chunk starting at chunk.ptr of size chunk.size
int write_chunk(fs_handle *handle, chunk_t chunk, const char *buffer);
// Writes over a chunk starting at chunk.ptr at offset start with a buffer of chunk.size bytes
uint64_t write_to_chunk(fs_handle *handle, chunk_t chunk, const char *buffer, uint64_t offset);
// Writes over a chunk chain starting at chunk.ptr at offset start with a buffer of chunk.size bytes
uint64_t write_to_data(fs_handle *handle, chunk_t chunk, const char *buffer, uint64_t offset);
// Appends to a chunk starting at ptr. The destination chunk starts at chunk_dest.ptr and has size chunk_dest.size
int append_to_data(fs_handle *handle, uint64_t ptr, chunk_t chunk_dest, const char *buffer);

// Reads the chunk starting at chunk.ptr. This chunk must have size >= chunk.size
uint64_t read_chunk(fs_handle *handle, chunk_t chunk, char *buffer, uint64_t offset);
// Reads the content of a chunk chain, starting at offset start. This chunk starts at chunk.ptr
// and has size at least chunk.size
uint64_t read_data(fs_handle *handle, chunk_t chunk, char *buffer, uint64_t offset);

char *read_inode_content(fs_handle *handle, const inode *node);
void replace_inode_content(fs_handle *handle, uint64_t node_ptr, const char *buffer, uint64_t size);

inode *create_inode(uint32_t uid, uint32_t gid, uint32_t mode, uint32_t size);

uint64_t get_tail_ptr(fs_handle *handle, uint64_t ptr);
int append_to_inode(fs_handle *handle, const char *buffer, uint64_t size, uint64_t node_ptr);
void add_child(fs_handle *handle, const char *filename, uint64_t parent_ptr, uint64_t node_ptr);

uint64_t make_file(fs_handle *handle, uint64_t parent_ptr, const char *name, const char *buffer, uint64_t size);
uint64_t make_directory(fs_handle *handle, uint64_t parent_ptr, const char *name);

inode *find_inode(fs_handle *handle, const char *path, uint64_t *node_ptr);

void free_chunks(fs_handle *handle, uint64_t ptr);
int free_inode(fs_handle *handle, uint64_t node_ptr);
int remove_directory(fs_handle *handle, uint64_t node_ptr);
int remove_file(fs_handle *handle, uint64_t node_ptr);

bool check_parity(fs_handle *handle, uint64_t stripe);
void simulate_drive_failure(fs_handle *handle, uint64_t drive);
void repair_failed_drive(fs_handle *handle, uint64_t drive);

#endif
