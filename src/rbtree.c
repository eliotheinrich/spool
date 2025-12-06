#include "rbtree.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static rb_node* make_node(void *data, void *augmented) {
  rb_node *n = malloc(sizeof(rb_node));
  if (!n) {
    return NULL;
  }
  n->data = data;
  n->augmented = augmented;
  n->color = RED;
  n->left = n->right = n->parent = NULL;
  return n;
}

rb_tree* rb_create(rb_less_fn less, rb_augment_fn aug, void *metadata) {
  rb_tree *t = malloc(sizeof(rb_tree));
  if (!t) {
    return NULL;
  }
  t->root = NULL;
  t->less = less;
  t->update_aug = aug;
  t->size = 0;
  t->metadata = metadata;
  return t;
}

rb_node* rb_root(rb_tree *t) { 
  return t->root; 
}

void update_augmented_upwards(rb_node *n, rb_tree *t) {
  if (!t->update_aug) {
    return;
  }

  while (n) {
    t->update_aug(n);
    n = n->parent;
  }
}

static void rotate_left(rb_tree *t, rb_node *x) {
  rb_node *y = x->right;

  x->right = y->left;
  if (y->left) {
    y->left->parent = x;
  }

  y->parent = x->parent;
  if (!x->parent) {
    t->root = y;
  } else if (x == x->parent->left) {
    x->parent->left = y;
  } else {
    x->parent->right = y;
  }

  y->left = x;
  x->parent = y;

  if (t->update_aug) {
    t->update_aug(x);
    t->update_aug(y);
  }
}

/* Right rotate x (mirror of left rotation) */
static void rotate_right(rb_tree *t, rb_node *x) {
  rb_node *y = x->left;

  x->left = y->right;
  if (y->right) {
    y->right->parent = x;
  }

  y->parent = x->parent;
  if (!x->parent) {
    t->root = y;
  } else if (x == x->parent->right) {
    x->parent->right = y;
  } else {
    x->parent->left = y;
  }

  y->right = x;
  x->parent = y;

  if (t->update_aug) {
    t->update_aug(x);
    t->update_aug(y);
  }
}

/* Fix red-black properties after inserting node n */
static void fix_insert(rb_tree *t, rb_node *n) {
  if (!n) {
    return;
  }

  while (n->parent && n->parent->color == RED) {
    rb_node *p = n->parent;
    rb_node *g = p->parent;
    if (!g) {
      break;
    }

    if (p == g->left) {
      rb_node *u = g->right; 
      if (u && u->color == RED) {
        p->color = BLACK;
        u->color = BLACK;
        g->color = RED;
        n = g;
      } else {
        if (n == p->right) {
          n = p;
          rotate_left(t, n);
          p = n->parent; 
          g = p ? p->parent : NULL;
          if (!p || !g) { 
            continue;
          }
        }
        p->color = BLACK;
        g->color = RED;
        rotate_right(t, g);
      }
    } else {
      rb_node *u = g->left;
      if (u && u->color == RED) {
        p->color = BLACK;
        u->color = BLACK;
        g->color = RED;
        n = g;
      } else {
        if (n == p->left) {
          n = p;
          rotate_right(t, n);
          p = n->parent;
          g = p ? p->parent : NULL;
          if (!p || !g) {
            continue;
          }
        }
        p->color = BLACK;
        g->color = RED;
        rotate_left(t, g);
      }
    }
  }
  if (t->root) t->root->color = BLACK;
}

const int ISUCCESS = 0b001;
const int IFAILED  = 0b010;
const int IREPLACE = 0b100;

int rb_insert(rb_tree *t, void *data, void *augmented) {
  if (!t) {
    return IFAILED;
  }

  rb_node *n = make_node(data, augmented);
  if (!n) {
    return IFAILED;
  }

  if (!t->root) {
    n->color = BLACK;
    t->root = n;
    t->size = 1;
    return ISUCCESS;
  }

  rb_node *cur = t->root;
  rb_node *parent = NULL;
  while (cur) {
    parent = cur;
    if (t->less(data, cur->data)) {
      cur = cur->left;
    } else if (t->less(cur->data, data)) {
      cur = cur->right;
    } else {
      free(cur->data);
      free(n);
      cur->data = data;
      return IREPLACE;
    }
  }

  n->parent = parent;
  if (t->less(data, parent->data)) {
    parent->left = n;
  } else {
    parent->right = n;
  }


  t->size++;
  update_augmented_upwards(n, t);
  fix_insert(t, n);
  return ISUCCESS;
}

/* Helper: find the minimum node starting from x */
static rb_node* minimum(rb_node *x) {
  while (x->left) {
    x = x->left;
  }
  return x;
}

static void transplant(rb_tree *t, rb_node *u, rb_node *v) {
  if (!u->parent) {
    t->root = v;
  } else if (u == u->parent->left) {
    u->parent->left = v;
  } else {
    u->parent->right = v;
  }

  if (v) {
    v->parent = u->parent;
  }

  if (t->update_aug) {
    update_augmented_upwards(u->parent, t);
  }
}

static void fix_delete(rb_tree *t, rb_node *x, rb_node *x_parent) {
  while (x != t->root && (!x || x->color == BLACK)) {
    rb_node *w;
    if (x == (x_parent ? x_parent->left : NULL)) {
      w = x_parent ? x_parent->right : NULL;
      if (w && w->color == RED) {
        w->color = BLACK;
        if (x_parent) {
          x_parent->color = RED;
        }
        rotate_left(t, x_parent);
        w = x_parent ? x_parent->right : NULL;
      }
      if (!w || ((!w->left || w->left->color == BLACK) &&
                 (!w->right || w->right->color == BLACK))) {
        if (w) {
          w->color = RED;
        }
        x = x_parent;
        x_parent = x ? x->parent : NULL;
      } else {
        if (!w->right || w->right->color == BLACK) {
          if (w->left) {
            w->left->color = BLACK;
          }
          w->color = RED;
          rotate_right(t, w);
          w = x_parent ? x_parent->right : NULL;
        }
        if (w) {
          w->color = x_parent->color;
        }
        if (x_parent) {
          x_parent->color = BLACK;
        }
        if (w && w->right) {
          w->right->color = BLACK;
        }
        rotate_left(t, x_parent);
        x = t->root;
        break;
      }
    } else {
      // Mirror of above
      w = x_parent ? x_parent->left : NULL;
      if (w && w->color == RED) {
        w->color = BLACK;
        if (x_parent) {
          x_parent->color = RED;
        }
        rotate_right(t, x_parent);
        w = x_parent ? x_parent->left : NULL;
      }
      if (!w || ((!w->left || w->left->color == BLACK) &&
                 (!w->right || w->right->color == BLACK))) {
        if (w) {
          w->color = RED;
        }
        x = x_parent;
        x_parent = x ? x->parent : NULL;
      } else {
        if (!w->left || w->left->color == BLACK) {
          if (w->right) {
            w->right->color = BLACK;
          }
          w->color = RED;
          rotate_left(t, w);
          w = x_parent ? x_parent->left : NULL;
        }
        if (w) {
          w->color = x_parent->color;
        }
        if (x_parent) {
          x_parent->color = BLACK;
        }
        if (w && w->left) {
          w->left->color = BLACK;
        }
        rotate_right(t, x_parent);
        x = t->root;
        break;
      }
    }
  }

  if (x) {
    x->color = BLACK;
  }
}

bool rb_delete(rb_tree *t, const void *key) {
  if (!t) {
    return false;
  }

  rb_node *z = t->root;

  while (z) {
    if (t->less(key, z->data)) {
      z = z->left;
    } else if (t->less(z->data, key)) {
      z = z->right;
    } else {
      break;
    }
  }

  if (!z) {
    printf("Returning early\n");
    return false; 
  }

  rb_node *y = z;
  rb_color y_original_color = y->color;
  rb_node *x = NULL;
  rb_node *first_aug_node = NULL;

  if (!z->left) {
    x = z->right;
    first_aug_node = z->parent;
    transplant(t, z, z->right);
  } else if (!z->right) {
    x = z->left;
    first_aug_node = z->parent;
    transplant(t, z, z->left);
  } else {
    y = minimum(z->right);
    y_original_color = y->color;
    x = y->right;
    if (y->parent == z) {
      first_aug_node = y;
      if (x) {
        x->parent = y;
      }
    } else {
      transplant(t, y, y->right);
      y->right = z->right;
      first_aug_node = y->parent;
      if (y->right) {
        y->right->parent = y;
      }
    }

    transplant(t, z, y);
    y->left = z->left;
    if (y->left) {
      y->left->parent = y;
    }
    y->color = z->color;
    first_aug_node = y;
  }

  if (y_original_color == BLACK) {
    fix_delete(t, x, first_aug_node);
  }

  free(z->augmented);
  free(z->data);
  free(z);
  t->size--;
  if (first_aug_node && t->update_aug) {
    update_augmented_upwards(first_aug_node, t);
  }
  return true;
}

void* rb_find(rb_tree *t, const void *key) {
  if (!t) {
    return NULL;
  }
  rb_node *cur = t->root;
  while (cur) {
    if (t->less(key, cur->data)) {
      cur = cur->left;
    } else if (t->less(cur->data, key)) {
      cur = cur->right;
    } else {
      return cur->data;
    }
  }
  return NULL;
}

// Next larger (successor) for any key
void* rb_next_larger(rb_tree *t, const void *key) {
  rb_node *cur = t->root;
  rb_node *succ = NULL;

  while (cur) {
    if (t->less(key, cur->data)) {
      succ = cur;     // current node is larger than key, candidate
      cur = cur->left;
    } else {
      cur = cur->right;
    }
  }

  return succ ? succ->data : NULL;
}

void* rb_next_smaller(rb_tree *t, const void *key) {
  rb_node *cur = t->root;
  rb_node *pred = NULL;

  while (cur) {
    if (t->less(cur->data, key)) {
      pred = cur;
      cur = cur->right;
    } else {
      cur = cur->left;
    }
  }

  return pred ? pred->data : NULL;
}

size_t rb_size(rb_tree *t) {
  if (!t) {
    return 0;
  }
  return t->size;
}

static void free_nodes(rb_node *n) {
  if (!n) {
    return;
  }

  free_nodes(n->left);
  free_nodes(n->right);
  free(n->data);
  free(n->augmented);
  free(n);
}

void rb_free(rb_tree *t) {
  if (!t) {
    return;
  }

  free_nodes(t->root);
  free(t);
}

block_t *make_block(int ptr, int size, rb_node **out_node) {
  block_t *blk = malloc(sizeof(block_t));
  blk->ptr = ptr;
  blk->size = size;

  rb_node *node = malloc(sizeof(rb_node));
  node->data = blk;
  node->augmented = malloc(sizeof(block_aug_t));
  ((block_aug_t *)node->augmented)->max_size = size;
  node->left = NULL;
  node->right = NULL;
  node->parent = NULL;
  node->color = RED;

  if (out_node) {
    *out_node = node;
  }
  return blk;
}

void update_max_size(rb_node *n) {
  block_t *blk = (block_t *)n->data;
  block_aug_t *aug = (block_aug_t *)n->augmented;

  int left_max = n->left ? ((block_aug_t *)n->left->augmented)->max_size : 0;
  int right_max = n->right ? ((block_aug_t *)n->right->augmented)->max_size : 0;

  aug->max_size = blk->size;
  if (left_max >= aug->max_size) {
    aug->max_size = left_max;
  }
  if (right_max > aug->max_size) {
    aug->max_size = right_max;
  }
}

bool block_less_by_ptr(const void *a, const void *b) {
  const block_t *ba = a;
  const block_t *bb = b;
  return ba->ptr < bb->ptr;
}

rb_tree *create_block_file_rbtree(uint64_t total_size) {
  uint64_t *ptr = malloc(sizeof(uint64_t));
  *ptr = total_size;
  rb_tree *t = rb_create(block_less_by_ptr, update_max_size, ptr);
  rb_mfree(t, 0, total_size);
  return t;
}

int rbtree_file_insert(rb_tree *t, uint64_t ptr, uint64_t size) {
  block_t *block = malloc(sizeof(block_t));
  block->ptr = ptr;
  block->size = size;
  block_aug_t *aug = malloc(sizeof(block_aug_t));
  aug->max_size = size;

  return rb_insert(t, block, aug);
}

int rbtree_file_delete(rb_tree *t, uint64_t ptr, uint64_t size) {
  block_t *block = malloc(sizeof(block_t));
  block->ptr = ptr;
  block->size = size;
  block_aug_t *aug = malloc(sizeof(block_aug_t));
  aug->max_size = size;

  return rb_delete(t, block);
}

void read_node_data(rb_node *node, uint64_t *ptr, uint64_t *size, uint64_t *max_size) {
  block_t *block = (block_t*)node->data;
  *ptr = block->ptr;
  *size = block->size;

  block_aug_t *aug = (block_aug_t*)node->augmented;
  *max_size = aug->max_size;
}

int rb_get_free_ptr(rb_tree* t, uint64_t size, uint64_t *ptr) {
  rb_node *node = t->root;
  uint64_t node_ptr, node_size, max_size;

  read_node_data(node, &node_ptr, &node_size, &max_size);
  if (max_size < size) {
    return -1;
  }

  bool keep_going = true;
  while (keep_going) {
    if (node->left && (((block_aug_t*)node->left->augmented)->max_size >= max_size)) {
      node = node->left;
    } else if (node->right && (((block_aug_t*)node->right->augmented)->max_size >= max_size)) {
      node = node->right;
    } else {
      // This is the terminal node
      keep_going = false;
    }

    read_node_data(node, &node_ptr, &node_size, &max_size);
  }

  *ptr = node_ptr;
  return 0;
}

// Frees the rbtree representation
int rb_mfree(rb_tree *t, uint64_t ptr, uint64_t size) {
  if (size == 0) {
    return 0;
  }

  uint64_t total_size = *((uint64_t*)t->metadata);
  // Out of bounds
  if (ptr + size > total_size) {
    return -1;
  }

  block_t *block = malloc(sizeof(block));
  block->ptr = ptr;
  block->size = size;

  // Deal with block starting at ptr
  block_t *b = (block_t*)rb_find(t, block);
  if (b) {
    uint64_t b_ptr = b->ptr;
    uint64_t b_size = b->size;
    rbtree_file_delete(t, b_ptr, b_size);

    if (b_size > size) {
      size = b_size;
    } 
  }

  block_t *prev = (block_t*)rb_next_smaller(t, block);
  block_t *next = (block_t*)rb_next_larger(t, block);

  // interval lies entirely within an existing free block
  // nothing needs to be done
  if (prev && prev->ptr + prev->size > ptr + size) {
    free(block);
    return 0;
  }

  // Address overlaps with neighboring sites
  // -----a*******b-------
  // --c****d-------------
  while (prev && prev->ptr + prev->size >= ptr) {
    uint64_t a = ptr;
    uint64_t c = prev->ptr;
    ptr = prev->ptr;
    size += a - c;
    rbtree_file_delete(t, prev->ptr, prev->size);
    prev = (block_t*)rb_next_smaller(t, block);
  }

  while (next && ptr + size >= next->ptr) {
    // -----a********b-------
    // ----------c*d---------
    // or 
    // ----------c*****d-----
    uint64_t d = next->ptr + next->size;
    uint64_t b = ptr + size;
    if (d > b) {
      size += d - b;
    }
    rbtree_file_delete(t, next->ptr, next->size);
    next = (block_t*)rb_next_larger(t, block);
  }
  
  // At this point, there are no overlaps. Insert and return
  rbtree_file_insert(t, ptr, size);
  free(block);
  return 0;
}

int rb_malloc(rb_tree *t, uint64_t ptr, uint64_t size) {
  if (size == 0) {
    return 0;
  }

  uint64_t total_size = *((uint64_t*)t->metadata);
  // Out of bounds
  if (ptr + size > total_size) {
    return -1;
  }

  block_t *block = malloc(sizeof(block));
  block->ptr = ptr;
  block->size = size;

  block_t *prev = (block_t*)rb_next_smaller(t, block);
  block_t *next = (block_t*)rb_next_larger(t, block);

  // Deal with block starting at ptr
  block_t *b = (block_t*) rb_find(t, block);
  if (b) {
    uint64_t b_ptr = b->ptr;
    uint64_t b_size = b->size;
    rbtree_file_delete(t, b_ptr, b_size);

    if (b_size > size) {
      rbtree_file_insert(t, b_ptr + size, b_size - size);
    }
  }

  // interval lies entirely within an existing free block
  while (prev && prev->ptr + prev->size > ptr + size) {
    // ---a******b------
    // -c***********d---
    uint64_t a = ptr;
    uint64_t b = ptr + size;
    uint64_t c = prev->ptr;
    uint64_t d = prev->ptr + prev->size;

    rbtree_file_delete(t, prev->ptr, prev->size);
    rbtree_file_insert(t, c, a - c);
    rbtree_file_insert(t, b, d - b);
    
    free(block);
    return 0;
  }

  // ---a******b------
  // -c***d-----------
  while (prev && prev->ptr + prev->size > ptr) {
    uint64_t a = ptr;
    uint64_t c = prev->ptr;
    rbtree_file_delete(t, prev->ptr, prev->size);
    rbtree_file_insert(t, c, a - c);
    prev = (block_t*)rb_next_smaller(t, block);
  }

  // ---a******b------
  // -----c******d----
  // or 
  // -----c**d--------
  while (next && ptr + size > next->ptr) {
    uint64_t b = ptr + size;
    uint64_t d = next->ptr + next->size;
    rbtree_file_delete(t, next->ptr, next->size);
    if (d > b) {
      rbtree_file_insert(t, b, d - b);
    }
    next = (block_t*)rb_next_larger(t, block);
  }
  
  free(block);
  return 0;
}

void print_tree_recursive(rb_node *n, int depth) {
  if (!n) {
    return;
  }

  // Indentation for current depth
  for (int i = 0; i < depth; i++) {
    printf("  ");
  }

  // Print current node info
  block_t *blk = (block_t *)n->data;
  block_aug_t *aug = (block_aug_t *)n->augmented;
  char color = n->color == RED ? 'R' : 'B';

  printf("[%li, %li] (color=%c", blk->ptr, blk->size, color);
  if (aug) {
    printf(", max_size=%li", aug->max_size);
  }
  printf(")\n");

  // Print right subtree first (so it appears on top when printed)
  print_tree_recursive(n->right, depth + 1);

  // Print left subtree
  print_tree_recursive(n->left, depth + 1);
}

void print_tree(rb_tree *t) {
  if (!t) {
    return;
  }
  printf("RB-tree (size=%zu):\n", t->size);
  print_tree_recursive(t->root, 0);
}

static size_t count_nodes(rb_node *n) {
  if (!n) {
    return 0;
  }
  return 1 + count_nodes(n->left) + count_nodes(n->right);
}

// Helper: Pre-order serialize
static void serialize_node(rb_node *n, char **buffer_ptr) {
  if (!n) {
    return;
  }

  block_t *b = (block_t*)n->data;
  memcpy(*buffer_ptr, &b->ptr, sizeof(uint64_t));
  *buffer_ptr += sizeof(uint64_t);

  memcpy(*buffer_ptr, &b->size, sizeof(uint64_t));
  *buffer_ptr += sizeof(uint64_t);

  **buffer_ptr = (char)n->color;
  *buffer_ptr += sizeof(char);

  serialize_node(n->left, buffer_ptr);
  serialize_node(n->right, buffer_ptr);
}

// Helper: Pre-order deserialize
static rb_node* deserialize_node(char **buffer_ptr, size_t *offset, size_t total_size, rb_tree *t) {
  size_t node_size = sizeof(uint64_t)*2 + sizeof(char);
  if (*offset + node_size > total_size) {
    return NULL;
  }

  block_t *b = malloc(sizeof(block_t));
  memcpy(&b->ptr, *buffer_ptr, sizeof(uint64_t));
  *buffer_ptr += sizeof(uint64_t);

  memcpy(&b->size, *buffer_ptr, sizeof(uint64_t));
  *buffer_ptr += sizeof(uint64_t);

  char color = **buffer_ptr;
  *buffer_ptr += sizeof(char);
  *offset += node_size;

  rb_node *n = malloc(sizeof(rb_node));
  n->data = b;
  n->augmented = malloc(sizeof(block_aug_t));
  ((block_aug_t*)n->augmented)->max_size = b->size;
  n->color = (rb_color)color;
  n->left = NULL;
  n->right = NULL;
  n->parent = NULL;

  n->left = deserialize_node(buffer_ptr, offset, total_size, t);
  if (n->left) {
    n->left->parent = n;
  }

  n->right = deserialize_node(buffer_ptr, offset, total_size, t);
  if (n->right) {
    n->right->parent = n;
  }

  t->update_aug(n);
  t->size++;
  return n;
}

char *rb_serialize(rb_tree *t, size_t *out_size) {
  if (!t) {
    return NULL;
  }

  size_t count = count_nodes(t->root);
  size_t buf_size = sizeof(uint64_t) + count * (sizeof(uint64_t)*2 + sizeof(char));

  char *buf = malloc(buf_size);

  char *ptr = buf;

  // Serialize metadata first
  memcpy(buf, t->metadata, sizeof(uint64_t));
  ptr += sizeof(uint64_t);

  // Serialize nodes
  serialize_node(t->root, &ptr);

  if (out_size) {
    *out_size = buf_size;
  }
  return buf;
}

int rb_deserialize(rb_tree *t, char *buffer, size_t size, rb_less_fn less, rb_augment_fn update_aug) {
  if (!t || !buffer) {
    return IFAILED;
  }

  char *ptr = buffer;
  size_t offset = 0;

  t->metadata = malloc(sizeof(uint64_t));
  memcpy(t->metadata, ptr, sizeof(uint64_t));
  ptr += sizeof(uint64_t);

  t->less = less;
  t->update_aug = update_aug;
  t->root = NULL;
  t->size = 0;

  t->root = deserialize_node(&ptr, &offset, size - sizeof(uint64_t), t);
  if (!t->root) {
    return IFAILED;
  }

  return ISUCCESS;
}

