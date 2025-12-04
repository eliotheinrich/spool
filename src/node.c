#include "node.h"

#include <string.h>
#include <stdio.h>

// Returns the root portion and the child of a path
#include <string.h>
#include <stdlib.h>

char *path_first(const char *path, const char **rest) {
  while (*path == '/') {
    path++;
  }
  if (!*path) { 
    *rest = NULL; 
    return NULL;
  }

  const char *start = path;
  while (*path && *path != '/') {
    path++;
  }

  char *first = strndup(start, path - start);

  while (*path == '/') {
    path++;
  }
  *rest = *path ? path : NULL;

  return first;
}

char *path_last(const char *path, const char **rest) {
    const char *start = path;
    const char *end = path + strlen(path);

    while (end > start && *(end-1) == '/') end--;
    if (end == start) {
        *rest = NULL;
        return NULL;
    }

    const char *p = end;
    while (p > start && *(p-1) != '/') p--;

    char *last = strndup(p, end - p);

    if (p > start) {
        // allocate rest on heap
        *rest = strndup(start, p - start - 1);  // parent path
    } else {
        *rest = strdup("/");  // root
    }

    return last;
}

char **split_string(const char *s, char delim) {
  if (!s) {
    return NULL;
  }

  if (s[0] == '\0') {
    char **result = malloc(sizeof(char*));
    result[0] = NULL;
    return result;
  }

  size_t count = 1;
  for (const char *p = s; *p; p++) {
    if (*p == delim) {
      count++;
    }
  }

  char **res = malloc((count + 1) * sizeof(char*));
  size_t i = 0;
  const char *start = s;
  for (const char *p = s; ; p++) {
    if (*p == delim || *p == '\0') {
      size_t len = p - start;
      res[i] = malloc(len + 1);
      memcpy(res[i], start, len);
      res[i][len] = '\0';
      i++;
      start = p + 1;
    }
    if (!*p) {
      break;
    }
  }

  res[i] = NULL;
  return res;
}

void remove_element(const char *data, size_t size, const char *str, char **out, size_t *out_size) {
  if (!data || !str || !out || !out_size) {
    return;
  }
  char *tmp = malloc(size);
  if (!tmp) {
    return;
  }
  size_t i = 0, w = 0;
  while (i + sizeof(uint64_t) <= size) {
    uint64_t id; 
    memcpy(&id, data + i, sizeof(uint64_t)); 
    i += sizeof(uint64_t);
    size_t start = i; 
    while (i < size && data[i] != ',') {
      i++;
    }
    size_t len = i - start;
    if (!(len == strlen(str) && memcmp(data + start, str, len) == 0)) {
      memcpy(tmp + w, &id, sizeof(uint64_t)); 
      w += sizeof(uint64_t);
      memcpy(tmp + w, data + start, len); 
      w += len;
      tmp[w++] = ',';
    }

    if (i < size && data[i] == ',') {
      i++;
    }
  }

  *out = tmp;
  *out_size = w;
}

void write_inode(char **storage, inode *node, uint64_t ptr) {
  uint64_t block = ptr / BLOCK_SIZE;
  uint64_t offset = ptr % BLOCK_SIZE;
  memcpy(storage[block] + offset, node, sizeof(inode));
}

inode *read_inode(char **storage, uint64_t ptr) {
  inode *node = malloc(sizeof(inode));
  uint64_t block = ptr / BLOCK_SIZE;
  uint64_t offset = ptr % BLOCK_SIZE;
  memcpy(node, storage[block] + offset, sizeof(inode));
  return node;
}

bool inodes_equal(inode *node1, inode *node2) {
  return memcmp(node1, node2, sizeof(inode)) == 0;
}

void print_inode(inode *node) {
  printf("mode = %i, uid = %i, gid = %i, atime = %i, mtime = %i, ctime = %i, ptr = %li, size = %li, link_count = %i\n",
          node->mode, node->uid, node->gid, node->atime, node->mtime, node->ctime, node->ptr, node->size, node->link_count);
}

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes

// Stores a block of data in storage starting at ptr
int write_chunk(char **storage, uint64_t ptr, uint64_t size, const char *data) {
  if (size == 0) {
    return 0;
  }

  uint64_t block = ptr / BLOCK_SIZE;
  uint64_t offset = ptr % BLOCK_SIZE;

  // Store header. Assume that data is stored contiguously for now, and that header fits in this block
  uint64_t next_ptr = 0;
  memcpy(storage[block] + offset, &next_ptr, sizeof(uint64_t));
  offset += sizeof(uint64_t);
  memcpy(storage[block] + offset, &size, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  uint64_t remaining_size = size;
  uint64_t cur_pos = 0;
  while (remaining_size > 0) {
    if (remaining_size < BLOCK_SIZE - offset) {
      // Can finish writing within this block
      memcpy(storage[block] + offset, data + cur_pos, remaining_size);
      offset += remaining_size;
      cur_pos += remaining_size;
      remaining_size = 0;
    } else {
      // Write as much as possible in this block
      uint64_t size_left_in_block = BLOCK_SIZE - offset;
      memcpy(storage[block] + offset, data + cur_pos, size_left_in_block);
      offset = 0;
      remaining_size -= size_left_in_block;
      cur_pos += size_left_in_block;
      block++;
    }

    if (block >= NUM_BLOCKS) {
      return -1;
    }
  }

  return 0;
}

int write_to_data(char **storage, uint64_t ptr, uint64_t size, const char *data, uint64_t start) {
  if (size == 0) {
    return 0;
  }

  uint64_t cur_pos = 0;
  uint64_t written_bytes = 0;
  while (written_bytes < size) {
    // For now, assume header fits in current block.
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;

    uint64_t chunk_size, next_ptr;
    memcpy(&next_ptr,   storage[block] + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(&chunk_size, storage[block] + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    uint64_t remaining_chunk_size;
    uint64_t skip;
    if (cur_pos + chunk_size < start) {
      cur_pos += chunk_size;
      ptr = next_ptr;
      continue;
    } else if (cur_pos < start) {
      skip = start - cur_pos;
      remaining_chunk_size = chunk_size - skip;
    } else {
      skip = 0;
      remaining_chunk_size = chunk_size;
    }

    cur_pos += skip;

    while (remaining_chunk_size > 0) {
      while (skip + offset > BLOCK_SIZE) {
        block++;
        cur_pos += BLOCK_SIZE;
        skip -= BLOCK_SIZE;
      }

      if (remaining_chunk_size < BLOCK_SIZE - offset - skip) {
        // Can finish reading within this block
        memcpy(storage[block] + offset + skip, data + written_bytes, remaining_chunk_size);
        written_bytes += remaining_chunk_size;
        cur_pos += remaining_chunk_size;
        remaining_chunk_size = 0;
      } else {
        // Read as much as possible in this block
        uint32_t size_left_in_block = BLOCK_SIZE - offset - skip;
        memcpy(storage[block] + offset + skip, data + written_bytes, size_left_in_block);
        written_bytes += size_left_in_block;
        offset = 0;
        remaining_chunk_size -= size_left_in_block;
        cur_pos += size_left_in_block;
        block++;
      }

      skip = 0;

      if (block >= NUM_BLOCKS) {
        free(data);
        return -1;
      }
    }
    ptr = next_ptr;
  }

  return 0;
}

int read_data_offset(const char **storage, uint64_t ptr, uint64_t size, char *data, uint64_t start) {
  if (size == 0) {
    return 0;
  }

  uint64_t cur_pos = 0;
  uint64_t read_bytes = 0;
  int k = 0;
  while (read_bytes < size && k++ < 10) {
    // For now, assume header fits in current block.
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;

    uint64_t chunk_size, next_ptr;
    memcpy(&next_ptr,   storage[block] + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(&chunk_size, storage[block] + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    uint64_t remaining_chunk_size;
    uint64_t skip;
    if (cur_pos + chunk_size < start) {
      cur_pos += chunk_size;
      ptr = next_ptr;
      continue;
    } else if (cur_pos < start) {
      // start lies somewhere in this chunk
      // -----------c----------s---------
      skip = start - cur_pos;
      remaining_chunk_size = chunk_size - skip;
    } else {
      skip = 0;
      remaining_chunk_size = chunk_size;
    }

    cur_pos += skip;

    while (remaining_chunk_size > 0) {
      while (skip + offset > BLOCK_SIZE) {
        block++;
        cur_pos += BLOCK_SIZE;
        skip -= BLOCK_SIZE;
      }

      if (remaining_chunk_size < BLOCK_SIZE - offset - skip) {
        // Can finish reading within this block
        memcpy(data + read_bytes, storage[block] + offset + skip, remaining_chunk_size);
        read_bytes += remaining_chunk_size;
        cur_pos += remaining_chunk_size;
        remaining_chunk_size = 0;
      } else {
        // Read as much as possible in this block
        uint32_t size_left_in_block = BLOCK_SIZE - offset - skip;
        memcpy(data + read_bytes, storage[block] + offset + skip, size_left_in_block);
        read_bytes += size_left_in_block;
        offset = 0;
        remaining_chunk_size -= size_left_in_block;
        cur_pos += size_left_in_block;
        block++;
      }

      skip = 0;

      if (block >= NUM_BLOCKS) {
        free(data);
        return -1;
      }
    }

    ptr = next_ptr;
  }

  return 0;
}

int read_data(const char **storage, uint64_t ptr, uint64_t size, char *data) {
  return read_data_offset(storage, ptr, size, data, 0);
}

char **malloc_blocks(int num_blocks, int block_size) {
  char **data = calloc(num_blocks, sizeof(char*));
  for (int i = 0; i < num_blocks; i++) {
    data[i] = calloc(block_size, 1);
  }

  return data;
}

uint64_t read_u64(const char *data) {
  uint64_t value;
  memcpy(&value, data, sizeof(uint64_t));
  return value;
}

void write_u64(char *data, uint64_t value) {
  memcpy(data, &value, sizeof(uint64_t));
}

// If inode is a directory, store data as 
// i N , i N , ... \0
// where i is the inode number, N is the same, and , is a comma.

char **get_subdirectories(const char *data, size_t data_size, uint64_t **inode_numbers) {
  if (!data || data_size < 8) {
    return NULL;
  }

  // First pass: count number of entries (count commas + 1)
  size_t count = 0;
  size_t i = 0;
  while (i + sizeof(uint64_t) <= data_size) {
    count++;
    // move past 8-byte inode
    i += sizeof(uint64_t);
    // skip string until comma or end
    while (i < data_size && data[i] != ',') {
      i++;
    }
    if (i < data_size && data[i] == ',') {
      i++;
    }
  }

  // Allocate arrays
  char **dirs = malloc((count + 1) * sizeof(char*));
  *inode_numbers = malloc(count * sizeof(uint64_t));

  i = 0;
  size_t k = 0;
  while (i + sizeof(uint64_t) <= data_size && k < count) {
    (*inode_numbers)[k] = read_u64(data + i);
    i += sizeof(uint64_t);

    size_t start = i;
    while (i < data_size && data[i] != ',') {
      i++;
    }
    size_t len = i - start;

    dirs[k] = malloc(len + 1);
    memcpy(dirs[k], data + start, len);
    dirs[k][len] = '\0';

    if (i < data_size && data[i] == ',') {
      i++;
    }

    k++;
  }

  dirs[count] = NULL;
  return dirs;
}

char *read_inode_content(const char **storage, const inode* node) {
  if (!node) {
    return NULL;
  }

  char *data = malloc(node->size);
  read_data(storage, node->ptr, node->size, data);
  return data;
}

char **init_filesystem(rb_tree **t) {
  char **storage = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);
  *t = create_block_file_rbtree(NUM_BLOCKS * BLOCK_SIZE);
  
  inode *root = malloc(sizeof(inode));
  root->uid = 0;
  root->gid = 0;
  root->mode = FILETYPE_DIR | FILETYPE_ROOT;
  root->size = 0;
  root->ptr = 0;

  rb_malloc(*t, ROOT_NODE, sizeof(inode));
  write_inode(storage, root, ROOT_NODE);

  free(root);
  return storage;
}

inode *create_inode(uint32_t uid, uint32_t gid, uint32_t mode, uint32_t size) {
  inode *node = malloc(sizeof(inode));
  node->uid = uid;
  node->gid = gid;
  node->mode = mode;
  node->size = size;
  node->link_count = 0;
  node->ptr = 0;

  return node;
}

uint64_t get_tail_ptr(const char **storage, uint64_t ptr) {
  uint64_t block = ptr / BLOCK_SIZE;
  uint64_t offset = ptr % BLOCK_SIZE;

  uint64_t prev_ptr = ptr;
  memcpy(&ptr, storage[block] + offset, sizeof(uint64_t));

  bool valid_ptr = (ptr != 0);
  while (valid_ptr) {
    block = ptr / BLOCK_SIZE;
    offset = ptr % BLOCK_SIZE;
    prev_ptr = ptr;
    memcpy(&ptr, storage[block] + offset, sizeof(uint64_t));
    valid_ptr = (ptr != 0);
  }

  return prev_ptr;
}

int append_to_inode(rb_tree *t, char **storage, const char *data, uint64_t size, uint64_t node_ptr) {
  inode *node = read_inode(storage, node_ptr);
  node->size += size;

  if (!node->ptr) {
    rb_get_free_ptr(t, HEADER_SIZE + size, &node->ptr);
    rb_malloc(t, node->ptr, HEADER_SIZE + size);
    write_chunk(storage, node->ptr, size, data);
  } else {
    uint64_t block = node->ptr / BLOCK_SIZE;
    uint64_t offset = node->ptr % BLOCK_SIZE;

    uint64_t ptr = read_u64(storage[block] + offset);

    uint64_t new_ptr;
    rb_get_free_ptr(t, HEADER_SIZE + size, &new_ptr);
    rb_malloc(t, new_ptr, HEADER_SIZE + size);
    write_chunk(storage, new_ptr, size, data);

    // Write pointer to next black at end of existing storage
    uint64_t tail_ptr = get_tail_ptr(storage, node->ptr);
    block = tail_ptr / BLOCK_SIZE;
    offset = tail_ptr % BLOCK_SIZE;
    write_u64(storage[block] + offset, new_ptr);
  }

  write_inode(storage, node, node_ptr);

  node = read_inode(storage, node_ptr);

  if (node_ptr == 48) {
    char *buf = malloc(node->size);
    read_data(storage, node->ptr, node->size, buf);
  }

  free(node);
  return 0;
}

void add_child(rb_tree *t, char **storage, const char *filename, uint64_t parent_ptr, uint64_t node_ptr) {
  // Append directory name to parent's content
  size_t size = strlen(filename) + 1 + sizeof(uint64_t);
  char *content = malloc(size);
  memcpy(content, &node_ptr, sizeof(uint64_t));

  for (int i = 0; i < strlen(filename); i++) {
    content[i + sizeof(uint64_t)] = filename[i];
  }
  content[strlen(filename) + sizeof(uint64_t)] = ',';

  append_to_inode(t, storage, content, size, parent_ptr);

  free(content);
}

void print_inode_format(char **storage, inode *node) {
  if (!node) {
    printf("NULL\n");
  }

  uint64_t ptr = node->ptr;
  int i = 0;
  printf("ptr to first chunk = %li\n", ptr);
  while (ptr) {
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;
    memcpy(&ptr,        storage[block] + offset,                    sizeof(uint64_t));
    uint64_t chunk_size;
    memcpy(&chunk_size, storage[block] + offset + sizeof(uint64_t), sizeof(uint64_t));

    printf("%i: (%li, %li)\n", i++, ptr, chunk_size);
  }
}

uint64_t make_file(rb_tree *t, char **storage, uint64_t parent_ptr, const char *name, const char *data, uint64_t size) {
  inode *node = create_inode(0, 0, FILETYPE_FILE, 0);
  node->size = size;
  node->link_count++;

  if (size > 0) {
    // Store data
    rb_get_free_ptr(t, HEADER_SIZE + size, &node->ptr);
    rb_malloc(t, node->ptr, HEADER_SIZE + node->size);
    write_chunk(storage, node->ptr, node->size, data);
  }

  // Store node
  uint64_t node_ptr;
  rb_get_free_ptr(t, sizeof(inode), &node_ptr);
  rb_malloc(t, node_ptr, sizeof(inode));
  write_inode(storage, node, node_ptr);

  free(node);

  add_child(t, storage, name, parent_ptr, node_ptr);

  return node_ptr;
}

uint64_t make_directory(rb_tree *t, char **storage, uint64_t parent_ptr, const char *name) {
  inode *node = create_inode(0, 0, FILETYPE_DIR, 0);
  node->link_count++;

  // Store node
  uint64_t node_ptr;
  rb_get_free_ptr(t, sizeof(inode), &node_ptr);
  rb_malloc(t, node_ptr, sizeof(inode));
  write_inode(storage, node, node_ptr);

  free(node);

  add_child(t, storage, name, parent_ptr, node_ptr);

  return node_ptr;
}

inode *find_inode(const char **storage, const char *path, uint64_t *node_ptr) {
  if (!path) {
    *node_ptr = 0;
    return read_inode(storage, ROOT_NODE);
  }

  if (path[0] == '/') {
    return find_inode(storage, path + 1, node_ptr);
  }

  char **path_elements = split_string(path, '/');
  inode *node = read_inode(storage, ROOT_NODE);
  *node_ptr = 0;

  while (*path_elements) {
    char *content = read_inode_content(storage, node);
    uint64_t *inode_ptrs;
    char **subdirs = get_subdirectories(content, node->size, &inode_ptrs);
    bool found = false;
    if (!subdirs) {
      return NULL;
    }

    int k = 0;
    while (subdirs[k]) {
      if (strcmp(path_elements[0], subdirs[k]) == 0) {
        node = read_inode(storage, inode_ptrs[k]);
        found = true;
        break;
      }
      k++;
    }

    if (found) {
      path_elements++;
      *node_ptr = inode_ptrs[k];
    } else {
      return NULL;
    }
  }

  return node;
}

void free_chunks(char **storage, rb_tree *t, uint64_t ptr) {
  while (ptr) {
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;

    uint64_t chunk_size, new_ptr;
    memcpy(&new_ptr,    storage[block] + offset,                    sizeof(uint64_t));
    memcpy(&chunk_size, storage[block] + offset + sizeof(uint64_t), sizeof(uint64_t));

    rb_mfree(t, ptr, chunk_size + HEADER_SIZE);
    ptr = new_ptr;
  }
}

void replace_inode_content(char **storage, rb_tree *t, uint64_t node_ptr, const char *data, uint64_t size) {
  inode *node = read_inode(storage, node_ptr);
  free_chunks(storage, t, node->ptr);
  free(node);

  append_to_inode(t, storage, data, size, node_ptr);
}

int free_inode(char **storage, rb_tree *t, uint64_t node_ptr) {
  inode *node = read_inode(storage, node_ptr);

  // Free data
  free_chunks(storage, t, node->ptr);

  // Free inode metadata
  rb_mfree(t, node_ptr, sizeof(inode));

  return 0;
}

int remove_directory(char **storage, rb_tree *t, uint64_t node_ptr) {
  inode *node = read_inode(storage, node_ptr);  
  if (!(node->mode & FILETYPE_DIR)) {
    free(node);
    return -1;
  }

  char *content = read_inode_content(storage, node);

  
  return free_inode(storage, t, node_ptr);
}

int remove_file(char **storage, rb_tree *t, uint64_t node_ptr) {
  inode *node = read_inode(storage, node_ptr);  
  if (!(node->mode & FILETYPE_FILE)) {
    free(node);
    return -1;
  }

  return free_inode(storage, t, node_ptr);
}

