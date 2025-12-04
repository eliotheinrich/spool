#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

#include "rbtree.h"
#include "node.h"

#define GET_MACRO(_1, _2, NAME, ...) NAME
#define ASSERT(...) GET_MACRO(__VA_ARGS__, ASSERT_TWO_ARGS, ASSERT_ONE_ARG)(__VA_ARGS__)

#define ASSERT_ONE_ARG(x) \
    do { if (!(x)) return false; } while (0)

#define ASSERT_TWO_ARGS(x, msg)                        \
    do {                                               \
        if (!(x)) {                                    \
            printf("%s\n", msg);                       \
            return false;                              \
        }                                              \
    } while (0)

typedef struct {
  const char *name;
  bool (*func)(void);
  bool passed;
  double duration;
} TestEntry;

typedef struct {
  TestEntry *items;
  size_t size;
  size_t cap;
} TestList;

static void testlist_init(TestList *t) {
  t->items = NULL;
  t->size = 0;
  t->cap = 0;
}

static void testlist_add(TestList *t, const char *name, bool (*func)(void), bool passed, double dur) {
  if (t->size == t->cap) {
    t->cap = t->cap ? t->cap * 2 : 8;
    t->items = realloc(t->items, t->cap * sizeof(TestEntry));
  }
  t->items[t->size++] = (TestEntry){ name, func, passed, dur };
}

static double now_seconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + tv.tv_usec / 1e6;
}

#define ADD_TEST(fn)                                                     \
    do {                                                                 \
        if (run_all || name_in_list(test_names, test_count, #fn)) {      \
            double start = now_seconds();                                \
            bool passed = fn();                                          \
            double stop = now_seconds();                                 \
            testlist_add(&tests, #fn "()", fn, passed, stop - start);    \
        }                                                                \
    } while (0)

static bool name_in_list(char **names, size_t count, const char *target) {
  for (size_t i = 0; i < count; i++) {
    if (strcmp(names[i], target) == 0) {
      return true;
    }
  }
  return false;
}

unsigned get_seed() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned seed = (unsigned) tv.tv_usec;
  return seed;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

bool test_remove_element() {
  char data[128]; 
  size_t size = 0;
  uint64_t id1 = 1,id2 = 2,id3 = 3;
  memcpy(data + size, &id1, 8); 
  size += 8; 
  memcpy(data + size,"foo",3); 
  size += 3; 
  data[size++] = ',';
  memcpy(data + size, &id2,8 );
  size += 8; 
  memcpy(data + size, "bar", 3); 
  size += 3; 
  data[size++] = ',';
  memcpy(data + size, &id3, 8); 
  size += 8; 
  memcpy(data + size, "baz", 3);
  size += 3; 
  data[size++] = ',';

  char *out = NULL; 
  size_t out_size = 0;
  remove_element(data, size, "bar", &out, &out_size);

  size_t i = 0; int count=0;
  while (i + sizeof(uint64_t) <= out_size) {
    uint64_t id; 
    memcpy(&id, out + i, sizeof(uint64_t)); 
    i += sizeof(uint64_t);
    size_t start = i; 
    while (i < out_size && out[i] != ',') {
      i++;
    }
    char *s = out + start; 
    size_t len = i - start;
    if (id == 1) { 
      if (len != 3 || strncmp(s, "foo", 3) != 0) {
        free(out); 
        return false; 
      }
    }
    else if (id == 3) { 
      if (len != 3 || strncmp(s, "baz", 3) != 0) {
        free(out); 
        return false; 
      } 
    }
    else { 
      free(out); 
      return false; 
    }
    count++; 
    i++;
  }

  free(out);
  return count == 2;
}

// Helper function to compare string arrays
bool compare_arrays(char **result, const char **expected, int count) {
  if (result == NULL && expected == NULL) {
    return true;
  }

  if (result == NULL || expected == NULL) {
    return false;
  }

  for (int i = 0; i < count; i++) {
    if (result[i] == NULL && expected[i] == NULL) {
      continue;
    }

    if (result[i] == NULL || expected[i] == NULL) {
      return false;
    }

    if (strcmp(result[i], expected[i]) != 0) {
      return false;
    }
  }

  // Check that result is NULL-terminated
  return result[count] == NULL;
}

// Helper function to free the result
void free_result(char **result) {
  if (result == NULL) return;
  for (int i = 0; result[i] != NULL; i++) {
    free(result[i]);
  }
  free(result);
}

bool test_split_string() {
  char **result;
  bool all_passed = true;

  // Test 1: Basic split with comma
  result = split_string("apple,banana,cherry", ',');
  const char *expected1[] = {"apple", "banana", "cherry", NULL};
  if (!compare_arrays(result, expected1, 3)) {
    printf("Test 1 failed: Basic split with comma\n");
    all_passed = false;
  }
  free_result(result);

  // Test 2: Split with spaces
  result = split_string("hello world test", ' ');
  const char *expected2[] = {"hello", "world", "test", NULL};
  if (!compare_arrays(result, expected2, 3)) {
    printf("Test 2 failed: Split with spaces\n");
    all_passed = false;
  }
  free_result(result);

  // Test 3: Empty string
  result = split_string("", ',');
  const char *expected3[] = {NULL};
  if (!compare_arrays(result, expected3, 0)) {
    printf("Test 3 failed: Empty string should return 0 elements\n");
    all_passed = false;
  }
  free_result(result);

  // Test 4: String with no delimiter
  result = split_string("hello", ',');
  const char *expected4[] = {"hello", NULL};
  if (!compare_arrays(result, expected4, 1)) {
    printf("Test 4 failed: String with no delimiter\n");
    all_passed = false;
  }
  free_result(result);

  // Test 5: Multiple consecutive delimiters
  result = split_string("a,,b,,,c", ',');
  const char *expected5[] = {"a", "", "b", "", "", "c", NULL};
  if (!compare_arrays(result, expected5, 6)) {
    printf("Test 5 failed: Multiple consecutive delimiters\n");
    all_passed = false;
  }
  free_result(result);

  // Test 6: Delimiter at start and end
  result = split_string(",hello,world,", ',');
  const char *expected6[] = {"", "hello", "world", "", NULL};
  if (!compare_arrays(result, expected6, 4)) {
    printf("Test 6 failed: Delimiter at start and end\n");
    all_passed = false;
  }
  free_result(result);

  // Test 7: Single character
  result = split_string("a", ',');
  const char *expected7[] = {"a", NULL};
  if (!compare_arrays(result, expected7, 1)) {
    printf("Test 7 failed: Single character\n");
    all_passed = false;
  }
  free_result(result);

  // Test 8: Only delimiters
  result = split_string(",,,", ',');
  const char *expected8[] = {"", "", "", "", NULL};
  if (!compare_arrays(result, expected8, 4)) {
    printf("Test 8 failed: Only delimiters\n");
    all_passed = false;
  }
  free_result(result);

  // Test 9: NULL input (if your function handles it)
  result = split_string(NULL, ',');
  if (result != NULL) {
    printf("Test 9 failed: NULL input should return NULL\n");
    all_passed = false;
    free_result(result);
  }

  return all_passed;
}

bool test_read_data_offset_basic() {
  unsigned seed = get_seed();
  printf("seed = %i\n", seed);
  srand(seed);

  char **storage = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);
  uint64_t block0 = 0;
  uint64_t offset0 = 4;
  uint64_t ptr0 = offset0 + block0*BLOCK_SIZE;
  uint64_t chunk_size0 = BLOCK_SIZE + 10;

  uint64_t block1 = 3;
  uint64_t offset1 = 5;
  uint64_t ptr1 = offset1 + block1*BLOCK_SIZE;
  uint64_t chunk_size1 = 6;

  uint64_t block2 = 5;
  uint64_t offset2 = 0;
  uint64_t ptr2 = offset2 + block2*BLOCK_SIZE;
  uint64_t chunk_size2 = 7;

  uint64_t size = chunk_size0 + chunk_size1 + chunk_size2;

  uint64_t zero = 0;
  memcpy(storage[block0] + offset0,                    &ptr1, sizeof(uint64_t));
  memcpy(storage[block0] + offset0 + sizeof(uint64_t), &chunk_size0, sizeof(uint64_t));

  memcpy(storage[block1] + offset1,                    &ptr2, sizeof(uint64_t));
  memcpy(storage[block1] + offset1 + sizeof(uint64_t), &chunk_size1, sizeof(uint64_t));

  memcpy(storage[block2] + offset2,                    &zero, sizeof(uint64_t));
  memcpy(storage[block2] + offset2 + sizeof(uint64_t), &chunk_size2, sizeof(uint64_t));

  for (uint64_t p = 0; p < chunk_size0; p++) {
    uint64_t ptr = p + ptr0 + 2*sizeof(uint64_t);
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;
    char val = p;
    *(storage[block] + offset) = val;
  }

  for (uint64_t p = 0; p < chunk_size1; p++) {
    uint64_t ptr = p + ptr1 + 2*sizeof(uint64_t);
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;
    uint64_t val = p + chunk_size0;
    *(storage[block] + offset) = val;
  }

  for (uint64_t p = 0; p < chunk_size2; p++) {
    uint64_t ptr = p + ptr2 + 2*sizeof(uint64_t);
    uint64_t block = ptr / BLOCK_SIZE;
    uint64_t offset = ptr % BLOCK_SIZE;
    uint64_t val = p + chunk_size0 + chunk_size1;
    *(storage[block] + offset) = val;
  }

  uint64_t offset = rand() % size;
  offset = 0;
  char *buffer = malloc(size - offset);
  read_data_offset(storage, ptr0, size - offset, buffer, offset);

  for (int i = 0; i < size - offset; i++) {
    ASSERT(buffer[i] == (char) i + offset);
  }

  free(buffer);
  free(storage);
  return true;
}

bool test_read_data_offset() {
  for (int k = 0; k < 10000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    rb_tree *t;
    char **storage = init_filesystem(&t);

    int n1 = 2*BLOCK_SIZE;
    int n2 = 4*BLOCK_SIZE;
    char *data1 = malloc(n1);
    char *data2 = malloc(n2);
    char *data3 = malloc(n1 + n2);

    for (int i = 0; i < n1; i++) {
      data1[i] = rand() % 92 + 32;
      data3[i] = data1[i];
    }
    for (int i = 0; i < n2; i++) {
      data2[i] = rand() % 92 + 32;
      data3[i + n1] = data2[i];
    }

    uint64_t node_ptr = make_file(t, storage, ROOT_NODE, "file", data1, n1);
    append_to_inode(t, storage, data2, n2, node_ptr);

    inode *node = read_inode(storage, node_ptr);
    uint64_t offset = rand() % n1;
    char *buffer = malloc(node->size - offset);
    read_data_offset(storage, node->ptr, node->size - offset, buffer, offset);

    for (int i = 0; i < n1 - offset; i++) {
      ASSERT(data1[i + offset] == buffer[i]);
    }

    free(data1);
    free(data2);
    free(data3);
    free(node);
    rb_free(t);
    free(storage);
  }
  return true;
}

bool test_write_data_offset() {
  for (int k = 0; k < 1000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    rb_tree *t;
    char **storage = init_filesystem(&t);

    int n1 = 2*BLOCK_SIZE;
    int n2 = 4*BLOCK_SIZE;
    char *data1 = malloc(n1);
    char *data2 = malloc(n2);
    char *data3 = malloc(n1 + n2);

    uint64_t ptr1 = 0;
    uint64_t ptr2 = 3*BLOCK_SIZE + 24;
    rb_malloc(t, ptr1, n1);
    write_chunk(storage, ptr1, n1, data1);
    memcpy(storage[ptr1/BLOCK_SIZE] + ptr1%BLOCK_SIZE, &ptr2, sizeof(uint64_t));
    rb_malloc(t, ptr2, n2);
    write_chunk(storage, ptr2, n2, data2);
    write_to_data(storage, ptr1, n1, data1, n1);

    int size = n1 + n2;

    uint64_t offset = n1;
    char *buffer = malloc(size - offset);
    read_data_offset(storage, ptr1, size - offset, buffer, offset);

    for (int i = 0; i < size - offset; i++) {
      ASSERT(data1[i] == buffer[i]);
    }

    free(data1);
    free(data2);
    free(data3);
    free(storage);
  }
  return true;
}

bool test_path_first_last() {
  const char *p = "a/b/c";
  const char *rest;

  /* first */
  char *f = path_first(p, &rest);
  if (!f) {
    return false;
  }
  if (strcmp(f, "a") != 0) { 
    free(f); 
    return false; 
  }
  if (!rest) { 
    free(f); 
    return false; 
  }
  if (strcmp(rest, "b/c") != 0) { 
    free(f); 
    return false; 
  }
  free(f);

  /* last */
  char *l = path_last(p, &rest);
  if (!l) {
    return false;
  }
  if (strcmp(l, "c") != 0) { 
    free(l); 
    return false; 
  }

  /* rest for last points into original string; compare prefix "a/b" */
  const char *expected_rest = "a/b";
  size_t erl = strlen(expected_rest);
  if (strncmp(rest, expected_rest, erl) != 0) { 
    free(l); 
    return false; 
  }
  /* ensure boundary is correct (next char is '/' or end) */
  if (rest[erl] != '/' && rest[erl] != '\0') { 
    free(l); 
    return false; 
  }

  free(l);
  return true;
}

void print_int_tree_recursive(rb_node *n, int depth) {
  if (!n) {
    return;
  }

  for (int i = 0; i < depth; i++) {
    printf("  ");
  }

  int *val = (int*)n->data;
  char color = n->color == RED ? 'R' : 'B';

  printf("[%d] (color=%c", *val, color);
  printf(")\n");

  print_int_tree_recursive(n->right, depth + 1);
  print_int_tree_recursive(n->left, depth + 1);
}

void print_int_tree(rb_tree *t) {
  if (!t) {
    return;
  }
  printf("RB-tree (size=%zu):\n", t->size);
  print_int_tree_recursive(t->root, 0);
}

bool int_less(const void *a, const void *b) {
  return *(int*)a < *(int*)b;
}

bool test_rbtree_basic() {
  rb_tree *t = rb_create(int_less, NULL, NULL);

  int *a = malloc(sizeof(int));
  *a = 10;
  int *b = malloc(sizeof(int));
  *b = 5;
  int *c = malloc(sizeof(int));
  *c = 20;
  int *d = malloc(sizeof(int));
  *d = 7;
  rb_insert(t, a, NULL);
  rb_insert(t, b, NULL);
  rb_insert(t, c, NULL);
  rb_insert(t, d, NULL);

  ASSERT(*(int*)rb_find(t, a) == 10);
  ASSERT(*(int*)rb_find(t, b) == 5);
  ASSERT(*(int*)rb_find(t, c) == 20);
  ASSERT(*(int*)rb_find(t, d) == 7);

  int missing = 99;
  ASSERT(rb_find(t, &missing) == NULL);

  rb_free(t);
  return true;
}

void collect_inorder(rb_node *n, int **out, size_t *idx) {
  if (!n) {
    return;
  }
  collect_inorder(n->left, out, idx);
  (*out)[(*idx)++] = *(int*)n->data;
  collect_inorder(n->right, out, idx);
}

bool test_rbtree_sorted_order() {
  srand(time(NULL));
  rb_tree *t = rb_create(int_less, NULL, NULL);

  const size_t N = 1000;
  int *vals = malloc(sizeof(int) * N);

  for (size_t i = 0; i < N; i++) {
    vals[i] = rand() % 100;
    int *v = malloc(sizeof(int));
    *v = vals[i];
    rb_insert(t, v, NULL);
  }

  int *ordered = malloc(sizeof(int) * N);
  size_t idx = 0;
  collect_inorder(t->root, &ordered, &idx);

  ASSERT(idx == rb_size(t));

  for (size_t i = 1; i < idx; i++) {
    ASSERT(ordered[i-1] <= ordered[i]);
  }

  free(ordered);
  free(vals);
  rb_free(t);
  return true;
}

bool test_rbtree_stress() {
  const size_t N = 5000;

  rb_tree *t = rb_create(int_less, NULL, NULL);
  int *vals = malloc(sizeof(int) * N);

  // Fill with random integers
  for (size_t i = 0; i < N; i++) {
    vals[i] = rand();
    int *v = malloc(sizeof(int));
    *v = vals[i];
    rb_insert(t, v, NULL);
  }

  // Lookup every value
  for (size_t i = 0; i < N; i++) {
    int *found = rb_find(t, &vals[i]);
    ASSERT(found != NULL);
    ASSERT(*found == vals[i]);
  }

  // Try some missing values
  int missing = -12345;
  ASSERT(rb_find(t, &missing) == NULL);

  free(vals);
  rb_free(t);
  return true;
}

bool test_rbtree_delete_randomized() {
  for (int k = 0; k < 10000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    rb_tree *t = rb_create(int_less, NULL, NULL);
    if (!t) {
      return false;
    }

    const size_t N = 100;
    int *vals = malloc(sizeof(int) * N);
    if (!vals) {
      return false;
    }

    int MAX = 200;

    // Insert all nodes
    for (size_t i = 0; i < N; i++) {
      vals[i] = rand() % MAX;
      int *key_copy = malloc(sizeof(int));
      *key_copy = vals[i];
      int result = rb_insert(t, key_copy, NULL);
      while (result == IREPLACE) {
        int *_key_copy = malloc(sizeof(int));
        vals[i] = rand() % MAX;
        *_key_copy = vals[i];

        result = rb_insert(t, _key_copy, NULL);
      }
    }

    // Verify size after insertions
    if (rb_size(t) != N) {
      printf("Size mismatch after insertions: %zu != %zu\n", rb_size(t), N);
      free(vals);
      rb_free(t);
      return false;
    }

    // Randomly delete about half of the nodes
    int num_deleted = 0;
    for (size_t i = 0; i < N / 2; i++) {
      size_t idx = rand() % N;
      if (vals[idx] == -1) {
        continue;
      }

      num_deleted++;

      int key = vals[idx];
      if (!rb_delete(t, &key)) {
        printf("Failed to delete %d\n", key);
        print_int_tree(t);
        free(vals);
        rb_free(t);
        return false;
      }

      vals[idx] = -1;

      // Optional: check size
      if (rb_size(t) != N - num_deleted) {
        printf("Size mismatch after deletion (%zu vs %zu)\n", N - num_deleted, rb_size(t));
        free(vals);
        rb_free(t);
        return false;
      }
    }

    // Verify remaining nodes are findable
    for (size_t i = 0; i < N; i++) {
      if (vals[i] != -1) {
        if (!rb_find(t, &vals[i])) {
          printf("Node %d not find after deletions!\n", vals[i]);
          free(vals);
          rb_free(t);
          return false;
        }
      }
    }

    rb_free(t);
    free(vals);
  }
  return true;
}

bool test_rbtree_successor_predecessor() {
  rb_tree *t = rb_create(int_less, NULL, NULL);
  ASSERT(t != NULL);

  int vals[] = {10, 20, 30, 40, 50};
  size_t n = sizeof(vals) / sizeof(vals[0]);

  for (size_t i = 0; i < n; i++) {
    int *v = malloc(sizeof(int));
    *v = vals[i];
    rb_insert(t, v, NULL);
  }

  // Test values that exist in the tree
  struct { int key; int expected_succ; int expected_pred; } tests1[] = {
    {10, 20, -1},
    {20, 30, 10},
    {30, 40, 20},
    {40, 50, 30},
    {50, -1, 40},
  };

  for (size_t i = 0; i < sizeof(tests1)/sizeof(tests1[0]); i++) {
    int key = tests1[i].key;
    int *succ = rb_next_larger(t, &key);
    int *pred = rb_next_smaller(t, &key);
    ASSERT(succ ? *succ == tests1[i].expected_succ : tests1[i].expected_succ == -1);
    ASSERT(pred ? *pred == tests1[i].expected_pred : tests1[i].expected_pred == -1);
  }

  // Test values not in the tree
  struct { int key; int expected_succ; int expected_pred; } tests2[] = {
    {5, 10, -1}, 
    {15, 20, 10},
    {25, 30, 20},
    {35, 40, 30},
    {45, 50, 40},
    {55, -1, 50},
  };

  for (size_t i = 0; i < sizeof(tests2)/sizeof(tests2[0]); i++) {
    int key = tests2[i].key;
    int *succ = rb_next_larger(t, &key);
    int *pred = rb_next_smaller(t, &key);
    ASSERT(succ ? *succ == tests2[i].expected_succ : tests2[i].expected_succ == -1);
    ASSERT(pred ? *pred == tests2[i].expected_pred : tests2[i].expected_pred == -1);
  }

  rb_free(t);
  return true;
}

// Augmentation: compute max size in subtree
bool test_rbtree_augmented_max_size() {
  rb_tree *t = create_block_file_rbtree(1000);
  if (!t) {
    return false;
  }

  int sizes[] = {10, 30, 20, 50, 15};
  int n_blocks = sizeof(sizes)/sizeof(sizes[0]);
  rb_node *nodes[n_blocks];

  // Insert blocks
  for (int i = 0; i < n_blocks; i++) {
    make_block(i*100, sizes[i], &nodes[i]);

    nodes[i]->augmented = malloc(sizeof(block_aug_t));
    block_aug_t *w = malloc(sizeof(block_aug_t));
    w->max_size = sizes[i];

    void *data = malloc(sizeof(block_t));
    memcpy(data, nodes[i]->data, sizeof(block_t));
    rb_insert(t, data, w);
  }

  //print_tree(t);

  // Check root's max_size
  block_aug_t *root_aug = (block_aug_t *)t->root->augmented;
  int expected_max = 50;
  ASSERT(root_aug->max_size = expected_max);

  // Delete the block with size 50
  rb_delete(t, nodes[3]->data);

  root_aug = (block_aug_t *)t->root->augmented;
  expected_max = 30; // next largest size
  ASSERT(root_aug->max_size == expected_max);

  rb_free(t);
  for (int i = 0; i < n_blocks; i++) {
    free(nodes[i]->augmented);
    free(nodes[i]->data);
    free(nodes[i]);
  }

  return true;
}

int check_max_size(rb_node *n) {
  if (!n) {
    return 0;
  }
  block_t *blk = (block_t *)n->data;

  int left_max = check_max_size(n->left);
  int right_max = check_max_size(n->right);

  int correct_max = blk->size;

  if (left_max > correct_max) {
    correct_max = left_max;
  }

  if (right_max > correct_max) {
    correct_max = right_max;
  }

  return correct_max;
}

bool validate_max_size(rb_node *node) {
  if (!node) {
    return true;
  }

  uint64_t max_size = ((block_aug_t*)node->augmented)->max_size;
  uint64_t size = ((block_t*)node->data)->size;

  bool valid = max_size >= size;
  if (node->left) {
    uint64_t left_max = ((block_aug_t*)node->left->augmented)->max_size;
    valid = valid && (max_size >= left_max) && validate_max_size(node->left);
  }

  if (node->right) {
    uint64_t right_max = ((block_aug_t*)node->right->augmented)->max_size;
    valid = valid && (max_size >= right_max) && validate_max_size(node->right);
  }

  return valid;
}

bool *to_bitmap(rb_tree *t, uint64_t total_width) {
  bool *freed = malloc(total_width*sizeof(bool));
  for (int j = 0; j < total_width; j++) {
    freed[j] = false;
  }
  
  void traverse(rb_node *node) {
    if (!node) {
      return;
    }

    traverse(node->left);

    block_t *block = (block_t *)node->data;
    uint64_t ptr  = block->ptr;
    uint64_t size = block->size;

    uint64_t end = ptr + size;
    if (end > total_width) {
      end = total_width;
    }

    for (uint64_t j = ptr; j < end; j++) {
      freed[j] = true;
    }

    traverse(node->right);
  }

  traverse(t->root);

  return freed;
}

bool test_rbtree_malloc_randomized() {
  for (int k = 0; k < 100; k++) {
    unsigned seed = get_seed();
    srand(seed);

    uint64_t total_size = 100;
    rb_tree *t = create_block_file_rbtree(total_size);

    bool *freed = malloc(total_size*sizeof(bool));
    for (int i = 0; i < total_size; i++) {
      freed[i] = true;
    }

    int nsteps = 10;
    int64_t *ptrs = malloc(sizeof(int64_t)*nsteps);
    int64_t *sizes = malloc(sizeof(int64_t)*nsteps);

    for (int i = 0; i < nsteps; i++) {
      int64_t r1 = rand() % total_size;
      int64_t r2 = rand() % total_size;
      while (abs(r2 - r1) < 2 && abs(r2 - r1) > 10) {
        r2 = rand() % total_size;
      }
      if (r1 > r2) {
        int64_t tmp = r2;
        r2 = r1;
        r1 = tmp;
      }

      ptrs[i] = r1;
      sizes[i] = r2 - r1;
    }

    for (int i = 0; i < nsteps; i++) {
      rb_malloc(t, ptrs[i], sizes[i]);
      for (int j = ptrs[i]; j < ptrs[i] + sizes[i]; j++) {
        freed[j] = false;
      }

      bool *freed_t = to_bitmap(t, total_size);
      for (int j = 0; j < total_size; j++) {
        ASSERT(freed[j] == freed_t[j]);
      }
      free(freed_t);
    }

    rb_free(t);
    free(ptrs);
    free(sizes);
    free(freed);
  }
  return true;
}

bool test_rbtree_mfree_basic() {
  uint64_t total_size = 10;
  rb_tree *t = create_block_file_rbtree(total_size);
  rb_malloc(t, 0, total_size);

  bool *freed = malloc(total_size*sizeof(bool));
  for (int i = 0; i < total_size; i++) {
    freed[i] = false;
  }

  uint64_t ptr = 5;
  uint64_t size = 3;
  rb_mfree(t, ptr, size);
  for (int j = ptr; j < ptr + size; j++) {
    freed[j] = true;
  }

  ptr = 3;
  size = 3;
  rb_mfree(t, ptr, size);
  for (int j = ptr; j < ptr + size; j++) {
    freed[j] = true;
  }

  ptr = 6;
  size = 3;
  rb_mfree(t, ptr, size);
  for (int j = ptr; j < ptr + size; j++) {
    freed[j] = true;
  }

  bool *freed_t = to_bitmap(t, total_size);
  for (int j = 0; j < total_size; j++) {
    ASSERT(freed[j] == freed_t[j]);
  }

  rb_free(t);
  free(freed);
  free(freed_t);
  return true;
}

bool test_rbtree_mfree_randomized() {
  for (int k = 0; k < 1000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    uint64_t total_size = 100;
    rb_tree *t = create_block_file_rbtree(total_size);
    rb_malloc(t, 0, total_size);

    bool *freed = malloc(total_size*sizeof(bool));
    for (int i = 0; i < total_size; i++) {
      freed[i] = false;
    }

    int nsteps = 10;
    int64_t *ptrs = malloc(sizeof(int64_t)*nsteps);
    int64_t *sizes = malloc(sizeof(int64_t)*nsteps);

    for (int i = 0; i < nsteps; i++) {
      int64_t r1 = rand() % total_size;
      int64_t r2 = rand() % total_size;
      while (abs(r2 - r1) < 2 || abs(r2 - r1) > 10) {
        r2 = rand() % total_size;
      }
      if (r1 > r2) {
        int64_t tmp = r2;
        r2 = r1;
        r1 = tmp;
      }

      ptrs[i] = r1;
      sizes[i] = r2 - r1;
    }

    for (int i = 0; i < nsteps; i++) {
      rb_mfree(t, ptrs[i], sizes[i]);
      for (int j = ptrs[i]; j < ptrs[i] + sizes[i]; j++) {
        freed[j] = true;
      }

      bool *freed_t = to_bitmap(t, total_size);
      for (int j = 0; j < total_size; j++) {
        ASSERT(freed[j] == freed_t[j]);
      }
      free(freed_t);
    }

    free(ptrs);
    free(sizes);
    free(freed);
    rb_free(t);
  }
  return true;
}

bool test_rbtree_free_ptr() {
  for (int k = 0; k < 1000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    uint64_t total_size = 100;
    rb_tree *t = create_block_file_rbtree(total_size);

    bool *freed = malloc(total_size*sizeof(bool));
    for (int i = 0; i < total_size; i++) {
      freed[i] = true;
    }

    int nsteps = 50;
    int64_t *ptrs = malloc(sizeof(int64_t)*nsteps);
    int64_t *sizes = malloc(sizeof(int64_t)*nsteps);

    for (int i = 0; i < nsteps; i++) {
      int64_t r1 = rand() % total_size;
      int64_t r2 = rand() % total_size;
      while (abs(r2 - r1) < 2 || abs(r2 - r1) > 10) {
        r2 = rand() % total_size;
      }
      if (r1 > r2) {
        int64_t tmp = r2;
        r2 = r1;
        r1 = tmp;
      }

      ptrs[i] = r1;
      sizes[i] = r2 - r1;
    }

    for (int i = 0; i < nsteps; i++) {
      float r = (float) rand()/INT_MAX;
      if (r < 0.75) {
        rb_malloc(t, ptrs[i], sizes[i]);
        for (int j = ptrs[i]; j < ptrs[i] + sizes[i]; j++) {
          freed[j] = false;
        }
      } else {
        rb_mfree(t, ptrs[i], sizes[i]);
        for (int j = ptrs[i]; j < ptrs[i] + sizes[i]; j++) {
          freed[j] = true;
        }
      }

      bool *freed_t = to_bitmap(t, total_size);
      bool valid = true;
      for (int j = 0; j < total_size; j++) {
        valid = valid && (freed[j] == freed_t[j]);
      }

      ASSERT(valid);
      free(freed_t);
    }


    block_aug_t *aug = (block_aug_t*)t->root->augmented;
    uint64_t max_size = aug->max_size;

    // Generate some pointers to free space and ensure that they are free
    for (int p = 0; p < 10; p++) {
      uint64_t ptr;
      uint64_t size = rand() % max_size;
      rb_get_free_ptr(t, size, &ptr);
      bool valid = true;
      for (int i = ptr; i < ptr + size; i++) {
        valid = valid && freed[i];
      }
      ASSERT(valid);
      ASSERT(validate_max_size(t->root));
    }

    free(ptrs);
    free(sizes);
    free(freed);
    rb_free(t);
  }

  return true;
}

bool test_get_subdirectories() {
  uint64_t ptrs[3] = {0x1000, 0x2000, 0x3000};
  const char *names[3] = {"testing1","testing2","testing3"};

  // Allocate for ptrs, names, commas, and null terminator
  size_t size = 3*sizeof(uint64_t) + strlen(names[0]) + strlen(names[1]) + strlen(names[2]) + 3 + 1;
  char *data = malloc(size);
  size_t off = 0;
  for (int i = 0; i < 3; i++){
    memcpy(data + off, &ptrs[i], sizeof(uint64_t));
    off += sizeof(uint64_t);
    size_t len = strlen(names[i]);
    memcpy(data + off, names[i], len); 
    off += len;
    if (i < 2) {
      data[off++] = ',';
    }
  }

  data[off] = '\0';

  uint64_t *inode_numbers;
  char **dirs = get_subdirectories(data, size, &inode_numbers);

  uint64_t num_dirs = 0;
  while (dirs[num_dirs]) {
    num_dirs++;
  }

  ASSERT(num_dirs == 3);

  for (int i = 0; i < 3; i++) {
    ASSERT(inode_numbers[i] == ptrs[i]);
    ASSERT(strcmp(dirs[i], names[i]) == 0);
  }

  free(inode_numbers);
  free(dirs);
  free(data);

  return true;
}

void print_storage(char **storage, int num_blocks, int block_size) {
  for (int k = 0; k < num_blocks; k++) {
    for (int i = 0; i < block_size; i++) {
      printf("%i ", storage[k][i]);
    } printf("\n");
  }
}

bool test_create_file() {
  rb_tree *t;
  char **storage = init_filesystem(&t);

  print_tree(t);

  uint64_t node1_ptr = make_directory(t, storage, ROOT_NODE,  "testing1");
  uint64_t node2_ptr = make_directory(t, storage, node1_ptr, "testing2");
  uint64_t node3_ptr = make_directory(t, storage, ROOT_NODE,  "testing3");

  inode *node1 = read_inode(storage, node1_ptr);
  inode *node3 = read_inode(storage, node3_ptr);
  
  print_tree(t);

  inode *root = read_inode(storage, ROOT_NODE);
  char *content = read_inode_content(storage, root);

  uint64_t *inode_numbers;
  char **subdirs = get_subdirectories(content, root->size, &inode_numbers);
  ASSERT(strcmp(subdirs[0], "testing1") == 0);
  ASSERT(strcmp(subdirs[1], "testing3") == 0);


  ASSERT(inodes_equal(read_inode(storage, inode_numbers[0]), node1), "Failed node comparison.");
  ASSERT(inodes_equal(read_inode(storage, inode_numbers[1]), node3), "Failed node comparison.");

  content = read_inode_content(storage, node1);
  subdirs = get_subdirectories(content, node1->size, &inode_numbers);
  ASSERT(strcmp(subdirs[0], "testing2") == 0);

  free(inode_numbers);
  free(content);
  free(subdirs);

  free(root);
  free(node1);
  free(node3);

  rb_free(t);
  free(storage);

  return true;
}

bool test_find_inode() {
  rb_tree *t;
  char **storage = init_filesystem(&t);

  uint64_t node1_ptr = make_directory(t, storage, ROOT_NODE,  "testing1");
  uint64_t node2_ptr = make_directory(t, storage, node1_ptr, "testing2");
  uint64_t node3_ptr = make_directory(t, storage, ROOT_NODE,  "testing3");
  char *success = "success";
  uint64_t node4_ptr = make_file(t, storage, node2_ptr,  "target", success, strlen(success));

  uint64_t node_ptr;
  inode *target = find_inode(storage, "/testing1/testing2/target", &node_ptr);
  char *content = read_inode_content(storage, target);

  ASSERT(strcmp(content, success) == 0);

  rb_free(t);
  free(storage);

  return true;
}


static const char *_GREEN = "\033[1;32m";
static const char *_RED   = "\033[1;31m";
static const char *_RESET = "\033[0m";

int main(int argc, char *argv[]) {
  TestList tests;
  testlist_init(&tests);

  bool run_all = (argc == 1);

  /* collect names from argv */
  char **test_names = NULL;
  size_t test_count = 0;

  if (!run_all) {
    test_count = argc - 1;
    test_names = &argv[1];
  }

  // Miscellaneous tests
  ADD_TEST(test_remove_element);
  ADD_TEST(test_split_string);

  // Storgae IO tests
  ADD_TEST(test_read_data_offset_basic);
  ADD_TEST(test_read_data_offset);
  ADD_TEST(test_path_first_last);
  ADD_TEST(test_write_data_offset);
  
  // rbtree basics
  ADD_TEST(test_rbtree_basic);
  ADD_TEST(test_rbtree_sorted_order);
  ADD_TEST(test_rbtree_stress);
  ADD_TEST(test_rbtree_delete_randomized);
  ADD_TEST(test_rbtree_successor_predecessor);
  ADD_TEST(test_rbtree_augmented_max_size);

  // rbtree filesystem allocation/free
  ADD_TEST(test_rbtree_malloc_randomized);
  ADD_TEST(test_rbtree_mfree_basic);
  ADD_TEST(test_rbtree_mfree_randomized);
  ADD_TEST(test_rbtree_free_ptr);

  // Directory traversal
  ADD_TEST(test_get_subdirectories);
  ADD_TEST(test_create_file);
  ADD_TEST(test_find_inode);

  if (tests.size == 0) {
    printf("No tests to run.\n");
    return 0;
  }

  bool all_passed = true;
  double total_duration = 0.0;

  for (size_t i = 0; i < tests.size; i++) {
    TestEntry *t = &tests.items[i];
    printf("%40s: %s%s%s (%.2f seconds)\n",
        t->name,
        t->passed ? _GREEN : _RED,
        t->passed ? "PASSED" : "FAILED",
        _RESET,
        t->duration
        );
    total_duration += t->duration;
    all_passed &= t->passed;
  }

  printf("Total duration: %.2f seconds\n", total_duration);

  free(tests.items);

  return all_passed ? 0 : 1;
}
