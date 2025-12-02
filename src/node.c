#include "node.h"

#include <string.h>
#include <stdio.h>

// Returns the root portion of the path
void split_path(const char* path, char** first, char** rest) {
  if (path[0] == '/') {
    path++;
  }

  const char* slash = strchr(path, '/');

  if (slash) {
    size_t len = slash - path;
    *first = malloc(len + 1);
    strncpy(*first, path, len);
    (*first)[len] = '\0';

    *rest = strdup(slash + 1); 
  } else {
    *first = strdup(path);  
    *rest = NULL;           
  }
}

void split_parent(const char *path, char **parent_out, char **name_out) {
  char *slash = strrchr(path, '/');

  if (!slash || slash == path) {
    *parent_out = strdup("/");
    *name_out = strdup(slash ? slash + 1 : path);
    return;
  }

  size_t parent_len = slash - path;
  *parent_out = malloc(parent_len + 1);
  strncpy(*parent_out, path, parent_len);
  (*parent_out)[parent_len] = 0;

  *name_out = strdup(slash + 1);
}

char **split_string(const char *s, char delim) {
  if (!s) {
    return NULL;
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

//static void write_u32(char **buf, uint32_t v) {
//  memcpy(*buf, &v, sizeof(v));
//  *buf += sizeof(v);
//}
//
//static uint32_t read_u32(const char **buf) {
//  uint32_t v;
//  memcpy(&v, *buf, sizeof(v));
//  *buf += sizeof(v);
//  return v;
//}
//
//static void write_bytes(char **buf, const void *src, size_t n) {
//  memcpy(*buf, src, n);
//  *buf += n;
//}
//
//static void read_bytes(const char **buf, void *dst, size_t n) {
//  memcpy(dst, *buf, n);
//  *buf += n;
//}
//
//size_t serialized_size(const Node *n) {
//  size_t s = 0;
//
//  s += sizeof(uint32_t) + strlen(n->name);       // name
//  s += sizeof(char);                             // type
//  s += sizeof(uint32_t);                         // size
//  s += sizeof(uint32_t) + n->size;               // content length + bytes
//  s += sizeof(uint32_t);                         // number of children
//
//  for (size_t i = 0; i < n->n_children; i++) {
//    s += serialized_size(n->children[i]);
//  }
//
//  return s;
//}
//
//void serialize_node(const Node *n, char **buf) {
//  uint32_t name_len = strlen(n->name);
//
//  // name
//  write_u32(buf, name_len);
//  write_bytes(buf, n->name, name_len);
//
//  // type
//  write_bytes(buf, &n->type, sizeof(char));
//
//  // content
//  write_u32(buf, n->size);
//  write_bytes(buf, n->content, n->size);
//
//  // number of children
//  write_u32(buf, (uint32_t)n->n_children);
//
//  // children
//  for (size_t i = 0; i < n->n_children; i++) {
//    serialize_node(n->children[i], buf);
//  }
//}
//
//char *write_tree(const Node *root, size_t *out_size) {
//  *out_size = serialized_size(root);
//  char *buffer = malloc(*out_size);
//  char *write_ptr = buffer;
//  serialize_node(root, &write_ptr);
//  return buffer;
//}
//
//Node *unserialize_node(const char **buf, Node *parent) {
//  Node *n = calloc(1, sizeof(Node));
//  n->parent = parent;
//
//  uint32_t name_len = read_u32(buf);
//  n->name = malloc(name_len + 1);
//  read_bytes(buf, n->name, name_len);
//  n->name[name_len] = '\0';
//
//  read_bytes(buf, &n->type, sizeof(char));
//
//  n->size = read_u32(buf);
//  uint32_t content_len = n->size;
//
//  if (content_len > 0) {
//    n->content = malloc(content_len);
//    read_bytes(buf, n->content, content_len);
//  }
//
//  uint32_t n_children = read_u32(buf);
//  n->n_children = n_children;
//  n->children = calloc(n_children, sizeof(Node*));
//
//  for (size_t i = 0; i < n_children; i++) {
//    n->children[i] = unserialize_node(buf, n);
//  }
//
//  return n;
//}
//
//Node *read_tree(const char *buffer) {
//  return unserialize_node(&buffer, NULL);
//}
//
//bool trees_equal(const Node *a, const Node *b) {
//  if (a == b) {
//    return true;
//  }
//
//  if (!a || !b) {
//    return false;
//  }
//
//  if (strcmp(a->name, b->name) != 0) {
//    return false;
//  }
//
//  if (a->type != b->type) {
//    return false;
//  }
//
//  if (a->size != b->size) {
//    return false;
//  }
//
//  if (a->size > 0 && memcmp(a->content, b->content, a->size) != 0) {
//    return false;
//  }
//
//  if (a->n_children != b->n_children) {
//    return false;
//  }
//
//  for (size_t i = 0; i < a->n_children; i++) {
//    if (!trees_equal(a->children[i], b->children[i])) {
//      return false;
//    }
//  }
//
//  return true;
//}
//
//
//Node *make_root() {
//  Node *root = malloc(sizeof(Node));
//  root->name = strdup("/");
//  root->type = FILETYPE_DIR;
//  root->children = NULL;
//  root->n_children = 0;
//  root->parent = NULL;
//  return root;
//}
//
//Node* load_filesystem(int backing_fd) {
//  Node* root = make_root();
//  return root;
//}
//
//Node* create_node(const char* name, const char* content, NodeType type) {
//  Node* node = malloc(sizeof(Node));
//  node->type = type;
//  node->name = strdup(name); 
//
//  if (type == FILETYPE_FILE && content) {
//    node->content = strdup(content); 
//    node->size = strlen(content);
//  } else {
//    node->content = NULL;
//    node->size = 0;
//  }
//
//  node->parent = NULL;
//  node->children = NULL;
//  node->n_children = 0;
//
//  return node;
//}
//
//void add_child(Node* parent, Node* child) {
//  Node** new_children = realloc(parent->children, (parent->n_children + 1) * sizeof(Node*));
//  if (!new_children) {
//    exit(1); 
//  }
//
//  parent->children = new_children;
//  parent->children[parent->n_children] = child; 
//  parent->n_children++; 
//  child->parent = parent;
//}
//
//void _print_tree(const Node *root, int depth) {
//  if (!root) {
//    return;
//  }
//
//  char* spaces = (char*)malloc(2*depth + 1);
//  memset(spaces, ' ', 2*depth);
//  spaces[2*depth] = '\0';
//
//  if (root->content) {
//    printf("%s%s: %s\n", spaces, root->name, root->content);
//  } else {
//    printf("%s%s\n", spaces, root->name);
//  }
//
//  for (int i = 0; i < root->n_children; i++) {
//    _print_tree(root->children[i], depth+1);
//  }
//}
//
//void print_tree(const Node *root) {
//  _print_tree(root, 0);
//}
//
//Node *find_node(Node *node, const char *path_) {
//  if (!node) {
//    return NULL;
//  }
//
//  if (!path_ || strcmp(path_, "/") == 0) {
//    return node;
//  }
//
//  char *path = malloc(strlen(path_) + 1);
//  strcpy(path, path_);
//
//  size_t len = strlen(path);
//
//  if (path[len - 1] == '/') {
//    path[len - 1] = '\0';
//  }
//
//  if (path[0] == '/') {
//    return find_node(node, path + 1);
//  }
//
//  if (strcmp(node->name, path) == 0) {
//    return node;
//  } else if (node->n_children > 0) {
//    char *part;
//    char *rest;
//    split_path(path, &part, &rest);
//
//    for (int i = 0; i < node->n_children; i++) {
//      Node *child = node->children[i];
//      if (!rest && strcmp(part, child->name) == 0) {
//        free(part);
//        free(rest);
//        return child;
//      } else if (child->type == FILETYPE_DIR && strcmp(part, child->name) == 0) {
//        Node *result = find_node(child, rest);
//        free(part);
//        free(rest);
//        return result;
//      }
//    }
//  }
//
//  return NULL;
//}
//
//void free_tree(Node* node) {
//  if (node == NULL) {
//    return;
//  }
//
//  for (int i = 0; i < node->n_children; i++) {
//    free_tree(node->children[i]);
//  }
//
//  free(node->children);
//  free(node->name);
//  free(node->content);
//  free(node);
//}
//

void write_inode(inode *node, int inode_number, char **metadata) {
  int inodes_per_block = BLOCK_SIZE / sizeof(inode);
  int block = 1 + (inode_number / inodes_per_block);
  int offset = (inode_number % inodes_per_block) * sizeof(inode);
  memcpy(metadata[block] + offset, node, sizeof(inode));
}

void read_inode(inode *node, int inode_number, char **metadata) {
  int inodes_per_block = BLOCK_SIZE / sizeof(inode);
  int block = 1 + (inode_number / inodes_per_block);
  int offset = (inode_number % inodes_per_block) * sizeof(inode);
  memcpy(node, metadata[block] + offset, sizeof(inode));
}

bool inodes_equal(inode *node1, inode *node2) {
  return memcmp(node1, node2, sizeof(inode)) == 0;
}

void print_inode(inode *node) {
  printf("mode = %i, uid = %i, gid = %i, atime = %i, mtime = %i, ctime = %i, ptr = %li, size = %i, link_count = %i\n",
          node->mode, node->uid, node->gid, node->atime, node->mtime, node->ctime, node->ptr, node->size, node->link_count);
}

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes

// Stores a block of data in storage starting at ptr
int write_data(uint64_t ptr, char *data, uint32_t size, char **storage) {
  int block = ptr / BLOCK_SIZE;
  int offset = ptr % BLOCK_SIZE;

  // Store header. Assume that data is stored contiguously for now.
  uint32_t next_ptr = 0;
  memcpy(storage[block] + offset, &size, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  printf("Wrote chunk_size = %li from %li, %li\n", size, block, offset);
  memcpy(storage[block] + offset, &next_ptr, sizeof(uint64_t));
  offset += sizeof(uint64_t);
  // For now, assume header fits in current block.

  uint32_t header_size = sizeof(uint32_t) + sizeof(uint64_t);

  uint32_t remaining_size = size;
  uint32_t cur_pos = 0;
  while (remaining_size > 0) {
    printf("remaining_size = %li\n", remaining_size);
    if (remaining_size < BLOCK_SIZE - offset) {
      // Can finish writing within this block
      printf("Finishing write within block. cur_pos = %li, block = %li, offset = %li\n", cur_pos, block, offset);
      memcpy(storage[block] + offset, data + cur_pos, remaining_size);
      offset += remaining_size;
      remaining_size = 0;
      cur_pos += remaining_size;
    } else {
      printf("Trying to write as much as possible in this block.\n");
      // Write as much as possible in this block
      uint32_t size_left_in_block = BLOCK_SIZE - offset;
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

int write_inode_data(inode *node, char *data, char **storage) {
  return write_data(node->ptr, data, node->size, storage);
}

int read_data(uint64_t ptr, char **data_ptr, uint32_t size, char **storage) {
  char *data = malloc(size*sizeof(char));

  uint32_t cur_pos = 0;
  while (size > 0) {
    printf("size = %li\n", size);
    // For now, assume header fits in current block.
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;

    uint32_t chunk_size = 0;
    uint64_t next_ptr = 0;
    memcpy(&chunk_size, storage[block] + offset, sizeof(uint32_t));
    printf("Read chunk_size = %li from %li, %li\n", chunk_size, block, offset);
    offset += sizeof(uint32_t);
    memcpy(&next_ptr,   storage[block] + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    while (chunk_size > 0) {
      printf("chunk_size = %li\n", chunk_size);
      if (chunk_size < BLOCK_SIZE - offset) {
        printf("Finishing read within block. chunk_size = %li, cur_pos = %li, block = %li, offset = %li\n", chunk_size, cur_pos, block, offset);
        // Can finish writing within this block
        memcpy(data + cur_pos, storage[block] + offset, chunk_size);
        offset += chunk_size;
        size -= chunk_size;
        cur_pos += chunk_size;
        chunk_size = 0;
      } else {
        // Write as much as possible in this block
        uint32_t size_left_in_block = BLOCK_SIZE - offset;
        memcpy(data + cur_pos, storage[block] + offset, size_left_in_block);
        offset = 0;
        size -= size_left_in_block;
        chunk_size -= size_left_in_block;
        cur_pos += size_left_in_block;
        block++;
      }

      if (block >= NUM_BLOCKS) {
        return -1;
      }
    }

    ptr = next_ptr;
  }


  *data_ptr = data;
  return 0;
}

int read_inode_data(inode *node, char **data_ptr, char **storage) {
  return read_data(node->ptr, data_ptr, node->size, storage);
}

inode *create_file(uint32_t uid, uint32_t gid, uint32_t size) {
  inode *node = malloc(sizeof(inode));

  node->uid = uid;
  node->gid = gid;
  node->mode = FILETYPE_FILE;
  node->size = size;
  get_free_ptr(size, &node->ptr);
  printf("header size = %li, size = %li, ptr = %li\n", sizeof(uint32_t) + sizeof(uint64_t), size, node->ptr);

  return node;
}

char **malloc_blocks(int num_blocks, int block_size) {
  char **data = malloc(num_blocks * sizeof(char*));
  for (int i = 0; i < num_blocks; i++) {
    data[i] = malloc(block_size);
  }

  return data;
}

void write_inode_metadata(inode *node, char *data, char **metadata) {
  uint32_t block = node->ptr / BLOCK_SIZE;
  uint32_t offset = node->ptr % BLOCK_SIZE;
  memcpy(metadata[block] + offset, data, node->size);
}

char *read_inode_metadata(inode *node, char **metadata) {
  char *data = malloc(sizeof(char)*node->size);
  uint32_t block = node->ptr / BLOCK_SIZE;
  uint32_t offset = node->ptr % BLOCK_SIZE;
  memcpy(data, metadata[block] + offset, node->size);
  return data;
}
