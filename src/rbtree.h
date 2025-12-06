#ifndef RBTREE_H
#define RBTREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { RED, BLACK } rb_color;

typedef struct rb_node {
  void *data;
  void *augmented; // Store thing like maximum size on each side
  rb_color color;
  struct rb_node *left;
  struct rb_node *right;
  struct rb_node *parent;
} rb_node;

typedef bool (*rb_less_fn)(const void*, const void*);
typedef void (*rb_augment_fn)(rb_node *n);

typedef struct rb_tree {
  rb_node *root;
  void *metadata;
  rb_less_fn less;
  rb_augment_fn update_aug;
  uint64_t size;
} rb_tree;

extern const int ISUCCESS;
extern const int IFAILED;
extern const int IREPLACE;

rb_tree* rb_create(rb_less_fn less, rb_augment_fn aug, void *metadata);
int rb_insert(rb_tree *t, void *data, void *augmented);
bool rb_delete(rb_tree *t, const void *key);
void* rb_find(rb_tree *t, const void *key);
void* rb_next_larger(rb_tree *t, const void *key);
void* rb_next_smaller(rb_tree *t, const void *key);
void rb_free(rb_tree *t);
size_t rb_size(rb_tree *t);
rb_node* rb_root(rb_tree *t);

// For detecting free blocks
typedef struct {
  uint64_t ptr;
  uint64_t size;
} block_t;

typedef struct {
  uint64_t max_size;
} block_aug_t;

rb_tree *create_block_file_rbtree(uint64_t total_size);
int rbtree_file_insert(rb_tree *t, uint64_t ptr, uint64_t size);
int rbtree_file_delete(rb_tree *t, uint64_t ptr, uint64_t size);

// Comparison by left edge of interval
bool block_less_by_ptr(const void *a, const void *b);

// Block-file rbtree
void update_max_size(rb_node *n);

// Helper to create a node with augmented data
block_t* make_block(int ptr, int size, rb_node **out_node);

// Assumes that tree stores ptr/size pairs and is augmented with max size
int rb_get_free_ptr(rb_tree* root, uint64_t size, uint64_t *ptr);
int rb_malloc(rb_tree *t, uint64_t ptr, uint64_t size);
int rb_mfree(rb_tree *t, uint64_t ptr, uint64_t size);

void update_augmented_upwards(rb_node *n, rb_tree *t);

void print_tree_recursive(rb_node *n, int depth);
void print_tree(rb_tree *t);

char *rb_serialize(rb_tree *t, size_t *out_size);
int rb_deserialize(rb_tree *t, char *buffer, size_t size, rb_less_fn less, rb_augment_fn update_aug);

#endif /* RBTREE_H */

