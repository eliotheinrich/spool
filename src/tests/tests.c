#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
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

int block = 0;
int offset = 0;

int get_free_ptr(uint64_t data_size, uint64_t *ptr) {
  // Need to store data and header
  uint64_t header_size = sizeof(uint64_t) + sizeof(uint64_t);
  uint64_t size = data_size + header_size;

  uint64_t cur_ptr = block * BLOCK_SIZE + offset;
  *ptr = cur_ptr;

  uint64_t remaining_size = size;
  while (offset + remaining_size >= BLOCK_SIZE) {
    block++;
    cur_ptr += BLOCK_SIZE;
    remaining_size -= BLOCK_SIZE;

    if (block >= NUM_BLOCKS) {
      return -1;
    }
  }

  cur_ptr += remaining_size;
  offset += remaining_size;

  return 0;
}

bool test_serialize_inode() {
  inode *node = create_file(1, 1, 10);
  uint64_t inode_number = 20;

  char **inode_metadata = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);

  write_inode(node, inode_number, inode_metadata);

  inode *new_node = malloc(sizeof(inode));
  read_inode(new_node, inode_number, inode_metadata);

  printf("Before: \n");
  print_inode(node);
  printf("After: \n");
  print_inode(new_node);

  ASSERT(inodes_equal(node, new_node));

  free(node);
  free(new_node);
  free(inode_metadata);
  return true;
}

bool test_get_inode_data() {
  char **storage = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);

  char *content = strdup("Hello, world!");
  int size = strlen(content);
  inode *node = create_file(0, 0, sizeof(char)*size);

  write_inode_metadata(node, content, storage);

  char *new_content = read_inode_metadata(node, storage);
  
  printf("Before storage: %s, after storage = %s\n", content, new_content); 
  ASSERT(strcmp(content, new_content) == 0);

  free(node);
  free(content);
  free(new_content);
  free(storage);
  return true;
}

bool test_files() {
  srand(time(NULL));
  
  uint64_t max_size = 4*BLOCK_SIZE;
  uint64_t min_size = 4;

  uint64_t num_files = 20;
  char **content = malloc(num_files*sizeof(char*));
  uint64_t *sizes = malloc(num_files*sizeof(uint64_t));

  char **storage = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);
  char **inode_metadata = malloc_blocks(NUM_BLOCKS, BLOCK_SIZE);

  for (int i = 0; i < num_files; i++) {
    sizes[i] = rand() % (max_size - min_size) + min_size;
    content[i] = malloc(sizes[i]*sizeof(char));
    for (int j = 0; j < sizes[i] - 1; j++) {
      content[i][j] = (char)(32 + rand() % 95);

    }
    content[i][sizes[i] - 1] = '\0';
  }

  inode **nodes = malloc(num_files*sizeof(inode*));

  for (int i = 0; i < num_files; i++) {
    nodes[i] = create_file(0, 0, sizeof(char)*sizes[i]);
    write_inode_data(nodes[i], content[i], storage);
  }

  for (int i = 0; i < num_files; i++) {
    char *result;
    read_inode_data(nodes[i], &result, storage);
    printf("Before: %s, after = %s, strlen = %li\n", content[i], result, strlen(result));
    ASSERT(strcmp(result, content[i]) == 0);
    free(result);
  }

  free(storage);
  free(inode_metadata);
  free(nodes);
  free(content);
  free(sizes);

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

  printf("[%d, %d] (color=%c", blk->ptr, blk->size, color);
  if (aug) {
    printf(", max_size=%d", aug->max_size);
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


bool int_less(const void *a, const void *b) {
  return *(int*)a < *(int*)b;
}

bool test_rbtree_basic() {
  rb_tree *t = rb_create(int_less, NULL, NULL);

  int a = 10, b = 5, c = 20, d = 7;
  rb_insert(t, &a, NULL);
  rb_insert(t, &b, NULL);
  rb_insert(t, &c, NULL);
  rb_insert(t, &d, NULL);

  ASSERT(*(int*)rb_find(t, &a) == 10);
  ASSERT(*(int*)rb_find(t, &b) == 5);
  ASSERT(*(int*)rb_find(t, &c) == 20);
  ASSERT(*(int*)rb_find(t, &d) == 7);

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
    rb_insert(t, &vals[i], NULL);
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

unsigned get_seed() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned seed = (unsigned) tv.tv_usec;
  return seed;
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
    rb_insert(t, &vals[i], NULL);
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

// Function to shuffle an array using Fisher-Yates algorithm
void shuffle(block_t *array, int n) {
  for (int i = n - 1; i > 0; i--) {
    int j = rand() % (i + 1); 
    block_t temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
}

bool test_rbtree_augmented_randomized() {
  for (int k = 0; k < 1000; k++) {
    unsigned seed = get_seed();
    srand(seed);

    rb_tree *t = create_block_file_rbtree(1000);
    if (!t) {
      return false;
    }

    const int N = 1000;
    int *sizes = malloc(sizeof(int)*N);
    int *ptrs = malloc(sizeof(int)*N);

    // Insert random blocks
    for (int i = 0; i < N; i++) {
      block_t *block = malloc(sizeof(block_t));
      block->ptr = rand() % 100000;
      block->size = rand() % 1000 + 1;
      ptrs[i] = block->ptr;
      sizes[i] = block->size;
      block_aug_t *aug = malloc(sizeof(block_aug_t));
      aug->max_size = block->size;
      rb_insert(t, block, aug);
    }

    check_max_size(t->root);

    // Randomly delete half of the blocks
    for (int i = 0; i < N/2; i++) {
      block_t *block = malloc(sizeof(block_t));
      block->ptr = ptrs[i];
      block->size = sizes[i];
      rb_delete(t, block);
      check_max_size(t->root);
    }

    rb_free(t);
    free(ptrs);
    free(sizes);
  }
  return true;
}

bool test_rbtree_free_ptr() {
  rb_tree *t = create_block_file_rbtree(1000);
  rbtree_file_insert(t, 0, 100);
  rbtree_file_insert(t, 150, 18);

  print_tree(t);
  uint64_t ptr;
  rb_get_free_ptr(t, 20, &ptr);
  printf("found ptr = %li\n", ptr);
  

  rb_free(t);
  return true;
}

bool test_rbtree_files_randomized() {
  uint64_t total_size = 1000;
  rb_tree *t = create_block_file_rbtree(total_size);

  bool *freed = malloc(total_size*sizeof(bool));
  for (int i = 0; i < total_size; i++) {
    freed[i] = true;
  }

  for (int i = 0; i < 100; i++) {
    int64_t r1 = rand() % total_size;
    int64_t r2 = rand() % total_size;
    while (abs(r2 - r1) < 4) {
      r2 = rand() % total_size;
    }
    if (r1 > r2) {
      int64_t tmp = r2;
      r2 = r1;
      r1 = tmp;
    }

    printf("r1 = %li, r2 = %li\n", r1, r2);

    uint64_t ptr = r1;
    uint64_t size = r2 - r1;

    for (int j = r1; j < r2; j++) {
      freed[j] = false;
    }

    rb_malloc(t, ptr, size);
  }

  print_tree(t);

  for (int j = 0; j < total_size; j++) {
    printf("freed = %i\n", freed[j]);
  }

  rb_free(t);
  return true;
};

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

  //ADD_TEST(test_serialize_tree);
  //ADD_TEST(test_find_node);

  //ADD_TEST(test_serialize_inode);
  //ADD_TEST(test_get_inode_data);
  //ADD_TEST(test_files);
  
  //ADD_TEST(test_rbtree_basic);
  //ADD_TEST(test_rbtree_sorted_order);
  //ADD_TEST(test_rbtree_stress);
  //ADD_TEST(test_rbtree_delete_randomized);
  //ADD_TEST(test_rbtree_successor_predecessor);
  //ADD_TEST(test_rbtree_augmented_max_size);
  //ADD_TEST(test_rbtree_augmented_randomized);

  ADD_TEST(test_rbtree_free_ptr);
  ADD_TEST(test_rbtree_files_randomized);

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
