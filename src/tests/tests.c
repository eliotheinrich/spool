#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

#include "thread_pool.h"
#include "rbtree.h"
#include "node.h"

static const uint32_t BLOCK_SIZE = 1024;
static const uint32_t NUM_BLOCKS = 20;


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

void *test_func(void* args) {
  int i = *(int*)args;
  int *ret = malloc(sizeof(int));
  *ret = i*i;
  return ret;
}

bool test_thread_pool() {
  thread_pool pool;
  thread_pool_init(&pool, 4);

  const int TASKS = 100;

  int args[TASKS];
  void *results[TASKS];

  // Assign ranges
  for (int i = 0; i < TASKS; i++) {
    args[i] = i;
    thread_pool_submit(&pool, test_func, &args[i], &results[i]);
  }

  thread_pool_wait(&pool);

  // Combine results
  for (int i = 0; i < TASKS; i++) {
    int *val = results[i];
    ASSERT(*val == i*i);
    free(val);
  }

  thread_pool_shutdown(&pool);

  return true;
}

bool test_write_chunk_basic() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  uint64_t data_ptr = 1024;
  chunk_t chunk;
  chunk.ptr  = data_ptr;  
  chunk.size = 8;

  const char data[8] = {1,2,3,4,5,6,7,8};

  if (write_chunk(handle, chunk, data) != 0) {
    return false;
  }

  // ----- Read back header -----
  read_chunk_header(handle, chunk.ptr, &chunk);
  uint64_t stored_ptr = chunk.ptr;
  uint64_t stored_size = chunk.size;

  if (stored_ptr != 0) {
    return false;
  }
  if (stored_size != 8) {
    return false;
  }

  // ----- Read back data -----
  data_ptr += sizeof(chunk_t);

  uint64_t data_drive = data_ptr / handle->drive_size;
  uint64_t data_offset = data_ptr % handle->drive_size;

  char buf[8] = {0};
  read_from_drive(handle, data_drive, data_offset, 8, buf);

  if (memcmp(buf, data, 8) != 0) {
    return false;
  }

  return true;
}

bool test_read_chunk_basic() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  const char payload[6] = {9,8,7,6,5,4};

  uint64_t data_ptr = 3000;
  chunk_t chunk;
  chunk.ptr = 0;
  chunk.size = 6;
  write_chunk_header(handle, data_ptr, &chunk);

  // Write payload
  uint64_t ddrive   = (data_ptr + sizeof(chunk_t)) / handle->drive_size;
  uint64_t doffset  = (data_ptr + sizeof(chunk_t)) % handle->drive_size;

  write_to_drive(handle, ddrive, doffset, 6, payload);

  // Now read using read_chunk()
  char buf[6] = {0};

  chunk.ptr  = data_ptr;
  chunk.size = 6;
  uint64_t n = read_chunk(handle, chunk, buf, 0);

  if (n != 6) return false;
  if (memcmp(buf, payload, 6) != 0) return false;

  return true;
}

bool test_read_chunk_with_offset() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  chunk_t chunk;
  chunk.ptr  = 500;
  chunk.size = 6;

  uint64_t next_ptr = 0;
  uint64_t size_hdr = 6;
  const char payload[6] = {10,11,12,13,14,15};

  // Write header
  write_chunk_header(handle, chunk.ptr, (chunk_t) {.ptr = 0, .size = chunk.size});

  // Write payload
  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t);
  uint64_t ddrive   = data_ptr / handle->drive_size;
  uint64_t doffset  = data_ptr % handle->drive_size;
  write_to_drive(handle, ddrive, doffset, size_hdr, payload);

  // Read final 3 bytes
  char buf[3] = {0};
  uint64_t n = read_chunk(handle, (chunk_t) {.ptr = chunk.ptr, .size = 3}, buf, 3);

  if (n != 3) {
    printf("Found n = %li\n", n);
    return false;
  }

  if (memcmp(buf, &payload[3], 3) != 0) {
    return false;
  }

  return true;
}

bool test_write_then_read_roundtrip() {
  int raid_levels[2] = {0, 5};
  for (int i = 0; i < 2; i++) {
    fs_handle *handle = init_filesystem(16, 4096, raid_levels[i]);

    chunk_t chunk;
    chunk.ptr  = 2048;
    chunk.size = 5;

    const char src[5] = {42,43,44,45,46};
    char dst[5] = {0};

    if (write_chunk(handle, chunk, src) != 0) {
      printf("Returned wrong number from write_chunk\n");
      return false;
    }

    uint64_t n = read_chunk(handle, chunk, dst, 0);

    if (n != 5) {
      printf("Read wrong number of bytes. n = %li\n", n);
      return false;
    }

    if (memcmp(src, dst, 5) != 0) {
      printf("Read wrong data\n");
      return false;
    }
  }

  return true;
}

bool test_write_to_chunk_basic() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  chunk_t chunk;
  chunk.ptr  = 2000;
  chunk.size = 10;

  const char initial[10] = {0,1,2,3,4,5,6,7,8,9};
  const char overwrite[4] = {50,51,52,53};

  // write initial chunk
  if (write_chunk(handle, chunk, initial) != 0) {
    return false;
  }

  // overwrite first 4 bytes
  uint64_t written = write_to_chunk(handle, (chunk_t) {.ptr = chunk.ptr, .size = 4}, overwrite, 0);

  if (written != 4) {
    return false;
  }

  // verify data
  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t);
  uint64_t drive    = data_ptr / handle->drive_size;
  uint64_t offset   = data_ptr % handle->drive_size;

  char result[10] = {0};
  read_from_drive(handle, drive, offset, 10, result);

  // expected result
  char expected[10] = {50,51,52,53,4,5,6,7,8,9};

  return memcmp(result, expected, 10) == 0;
}

bool test_write_to_chunk_middle() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  chunk_t chunk;
  chunk.ptr = 4096;        // drive 1
  chunk.size = 12;

  char initial[12];
  for (int i = 0; i < 12; i++) {
    initial[i] = i;
  }

  const char overwrite[3] = {100,101,102};

  if (write_chunk(handle, chunk, initial) != 0) {
    return false;
  }

  uint64_t written = write_to_chunk(handle, (chunk_t) {.ptr = chunk.ptr, .size = 3}, overwrite, 5);
  if (written != 3) {
    return false;
  }

  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t);
  uint64_t drive    = data_ptr / handle->drive_size;
  uint64_t offset   = data_ptr % handle->drive_size;

  char *result = malloc(12);
  read_from_drive(handle, drive, offset, 12, result);

  char *expected = malloc(12);
  for (int i = 0; i < 12; i++) {
    expected[i] = i;
  }
  expected[5] = 100;
  expected[6] = 101;
  expected[7] = 102;

  ASSERT(memcmp(result, expected, 12) == 0);

  free(expected);
  free(result);
  free_handle(handle);
  return true;
}

bool test_write_to_chunk_exact_end() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  chunk_t chunk;
  chunk.ptr = 1234;
  chunk.size = 6;

  char *initial = malloc(6);
  initial[0] = 10; initial[1] = 20; initial[2] = 30; initial[3] = 40; initial[4] = 50; initial[5] = 60;
  char *overwrite = malloc(2);
  overwrite[0] = 99; overwrite[1] = 98;

  if (write_chunk(handle, chunk, initial) != 0) {
    return false;
  }

  uint64_t written = write_to_chunk(handle, (chunk_t) {.ptr = chunk.ptr, .size = 2}, overwrite, 4);

  if (written != 2) {
    return false;
  }

  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t);
  uint64_t drive    = data_ptr / handle->drive_size;
  uint64_t offset   = data_ptr % handle->drive_size;

  char *result = malloc(6);
  read_from_drive(handle, drive, offset, 6, result);

  char *expected = malloc(6);
  expected[0] = 10; expected[1] = 20; expected[2] = 30; expected[3] = 40; expected[4] = 99; expected[5] = 98;

  ASSERT(memcmp(result, expected, 6) == 0);

  free(result);
  free(expected);
  free(initial);
  free(overwrite);
  free_handle(handle);

  return true;
}

bool test_write_to_chunk_past_end() {
  fs_handle *handle = init_filesystem(16, 4096, 0);

  chunk_t chunk;
  chunk.ptr = 300;
  chunk.size = 5;

  const char initial[5] = {1,2,3,4,5};
  const char overwrite[5] = {70,71,72,73,74};

  if (write_chunk(handle, chunk, initial) != 0) {
    return false;
  }

  // Start at offset 3 → only 2 bytes should be writable (chunk.size - 3)
  uint64_t written = write_to_chunk(handle, (chunk_t) {.ptr = chunk.ptr, .size = 5}, overwrite, 3);

  if (written != 2) {
    return false;
  }

  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t);
  uint64_t drive    = data_ptr / handle->drive_size;
  uint64_t offset   = data_ptr % handle->drive_size;

  char *result = malloc(5);
  read_from_drive(handle, drive, offset, 5, result);

  char *expected = malloc(5);
  expected[0] = 1; expected[1] = 2; expected[2] = 3; expected[3] = 70; expected[4] = 71;

  ASSERT(memcmp(result, expected, 5) == 0);

  free(result);
  free(expected);
  free_handle(handle);

  return true;
}

bool test_write_to_data_multidrive() {
  int raid_levels[2] = {5};
  for (int i = 0; i < 2; i++) {
    fs_handle *handle = init_filesystem(32, 4000, raid_levels[i]);

    const int Asize = 6000;
    const int Bsize = 3000;
    uint64_t Coffset = 4000;
    uint64_t Csize = 3000;

    const uint64_t Aptr = 1000 / handle->stripe_size * handle->stripe_size; // 3000
    const uint64_t Bptr = 9000 / handle->stripe_size * handle->stripe_size; // 9000

    // Chunk A (spans 2 blocks)
    chunk_t A = { .ptr = Aptr, .size = Asize };
    // Chunk B (another drive-spanning chunk)
    chunk_t B = { .ptr = Bptr, .size = Bsize };


    // Prepare data
    char *Adata = malloc(Asize);
    char *Bdata = malloc(Bsize);
    for (int i = 0; i < Asize; i++) {
      Adata[i] = (char)(i & 0xFF);
    }
    for (int i = 0; i < Bsize; i++) {
      Bdata[i] = (char)(50 + (i & 0x1F));
    }

    // Round-trip write and verify write_chunk():
    if (write_chunk(handle, A, Adata) != 0) {
      printf("Failed write_chunk\n");
      return false;
    }

    if (append_to_data(handle, A.ptr, B, Bdata) != 0) {
      printf("Failed append_to_data\n");
      return false;
    }

    // New data that will cross A → B boundary
    char *newdata = malloc(Bsize);
    for (int i = 0; i < Bsize; i++) {
      newdata[i] = (char)(200 + (i & 0x3F));
    }

    // Write starting 1000 bytes before end of A (1000 in A, 2000 in B)
    uint64_t rc = write_to_data(handle, (chunk_t) {.ptr = A.ptr, .size = Csize}, newdata, Coffset);
    if (rc != Csize) {
      printf("Failed write_to_data\n");
      return false;
    }

    // Verify A
    char *Aread = malloc(Asize);
    read_chunk(handle, A, Aread, 0);

    for (int i = 0; i < Coffset; i++) {
      if (Aread[i] != Adata[i]) {
        printf("Data read incorrectly (1) at site %li\n", i);
        return false;
      }
    }

    for (int i = 0; i < Asize - Coffset; i++) {
      if (Aread[Coffset + i] != newdata[i]) {
        printf("Data read incorrectly (2) at site %li\n", i);
        return false;
      }
    }

    // Verify B
    char *Bread = malloc(Bsize);
    read_chunk(handle, B, Bread, 0);

    // Overlap with A:
    for (int i = 0; i < Csize - Asize + Coffset; i++) {
      if (Bread[i] != newdata[Asize - Coffset + i]) {
        printf("Data read incorrectly (3) at site %li Coffset = %li. j = %li\n", i, Coffset, Asize - Coffset + i);
        return false;
      }
    }

    for (int i = Bsize - Asize + Coffset; i < Bsize; i++) {
      if (Bread[i] != Bdata[i]) {
        printf("Data read incorrectly (4) at site %li\n", i);
        return false;
      }
    }

    free(Adata);
    free(Bdata);
    free(newdata);
    free(Aread);
    free(Bread);
    free_handle(handle);
  }

  return true;
}

bool test_read_data_multidrive() {
  fs_handle *handle = init_filesystem(32, 4096, 0);

  chunk_t A = { .ptr = 2000,  .size = 7000 };
  chunk_t B = { .ptr = 13000, .size = 4000 };

  char *Adata = malloc(7000);
  char *Bdata = malloc(4000);
  for (int i = 0; i < 7000; i++) {
    Adata[i] = (char)(i & 0x7F);
  }
  for (int i = 0; i < 4000; i++) {
    Bdata[i] = (char)(120 + (i & 0x3F));
  }

  // A → B
  if (write_chunk(handle, A, Adata) != 0) {
    return false;
  }

  if (append_to_data(handle, A.ptr, B, Bdata) != 0) {
    return false;
  }

  // Read 5000 bytes starting at offset 4000 (3000 from A, 2000 from B)
  char *out = malloc(5000);
  chunk_t c = {.ptr = A.ptr, .size = 5000};
  if (read_data(handle, c, out, 4000) != 5000) {
    return false;
  }

  // 3000 from A
  for (int i = 0; i < 3000; i++) {
    if (out[i] != Adata[4000 + i]) {
      return false;
    }
  }

  // 2000 from B
  for (int i = 0; i < 2000; i++) {
    if (out[3000 + i] != Bdata[i]) {
      return false;
    }
  }

  free(Adata);
  free(Bdata);
  free(out);
  free_handle(handle);
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
  rb_tree *t = create_chunk_file_rbtree(1000);
  if (!t) {
    return false;
  }

  int sizes[] = {10, 30, 20, 50, 15};
  int n_blocks = sizeof(sizes)/sizeof(sizes[0]);
  rb_node *nodes[n_blocks];

  // Insert blocks
  for (int i = 0; i < n_blocks; i++) {
    make_chunk(i*100, sizes[i], &nodes[i]);

    nodes[i]->augmented = malloc(sizeof(chunk_aug_t));
    chunk_aug_t *w = malloc(sizeof(chunk_aug_t));
    w->max_size = sizes[i];

    void *data = malloc(sizeof(chunk_t));
    memcpy(data, nodes[i]->data, sizeof(chunk_t));
    rb_insert(t, data, w);
  }

  // Check root's max_size
  chunk_aug_t *root_aug = (chunk_aug_t *)t->root->augmented;
  int expected_max = 50;
  ASSERT(root_aug->max_size = expected_max);

  // Delete the drive with size 50
  rb_delete(t, nodes[3]->data);

  root_aug = (chunk_aug_t *)t->root->augmented;
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

// Helper to compare two trees recursively
bool compare_nodes(rb_node *a, rb_node *b) {
  if (!a && !b) {
    return true;
  }
  if (!a || !b) {
    return false;
  }

  chunk_t *ba = (chunk_t*)a->data;
  chunk_t *bb = (chunk_t*)b->data;

  if (ba->ptr != bb->ptr || ba->size != bb->size) {
    return false;
  }

  chunk_aug_t *aug_a = (chunk_aug_t*)a->augmented;
  chunk_aug_t *aug_b = (chunk_aug_t*)b->augmented;

  if (aug_a->max_size != aug_b->max_size) {
    return false;
  }

  if (a->color != b->color) {
    return false;
  }

  return compare_nodes(a->left, b->left) && compare_nodes(a->right, b->right);
}

bool test_rbtree_serialize() {
  // Create first tree
  rb_tree *t1 = create_chunk_file_rbtree(1024);
  uint64_t* metadata = malloc(sizeof(uint64_t)); 
  *metadata = 42;
  t1->metadata = (void*)metadata;  

  // Allocate some blocks
  rb_malloc(t1, 0, 256);
  rb_malloc(t1, 256, 128);
  rb_malloc(t1, 384, 64);

  // Serialize
  size_t buf_size;
  char *buffer = rb_serialize(t1, &buf_size);
  if (!buffer) {
    rb_free(t1);
    return false;
  }

  // Deserialize into new tree
  rb_tree *t2 = create_chunk_file_rbtree(1024);
  int res = rb_deserialize(t2, buffer, buf_size, t1->less, t1->update_aug);
  if (res != ISUCCESS) {
    free(buffer);
    rb_free(t1);
    rb_free(t2);
    return false;
  }

  // Compare both trees
  bool equal = compare_nodes(t1->root, t2->root) && *(uint64_t*)t1->metadata == *(uint64_t*)t2->metadata;

  free(buffer);
  rb_free(t1);
  rb_free(t2);

  return equal;
}

int check_max_size(rb_node *n) {
  if (!n) {
    return 0;
  }
  chunk_t *blk = (chunk_t *)n->data;

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

  uint64_t max_size = ((chunk_aug_t*)node->augmented)->max_size;
  uint64_t size = ((chunk_t*)node->data)->size;

  bool valid = max_size >= size;
  if (node->left) {
    uint64_t left_max = ((chunk_aug_t*)node->left->augmented)->max_size;
    valid = valid && (max_size >= left_max) && validate_max_size(node->left);
  }

  if (node->right) {
    uint64_t right_max = ((chunk_aug_t*)node->right->augmented)->max_size;
    valid = valid && (max_size >= right_max) && validate_max_size(node->right);
  }

  return valid;
}

void traverse(rb_node *node, uint64_t total_width, bool *freed) {
  if (!node) {
    return;
  }

  traverse(node->left, total_width, freed);

  chunk_t *drive = (chunk_t *)node->data;
  uint64_t ptr  = drive->ptr;
  uint64_t size = drive->size;

  uint64_t end = ptr + size;
  if (end > total_width) {
    end = total_width;
  }

  for (uint64_t j = ptr; j < end; j++) {
    freed[j] = true;
  }

  traverse(node->right, total_width, freed);
}


bool *to_bitmap(rb_tree *t, uint64_t total_width) {
  bool *freed = malloc(total_width*sizeof(bool));
  for (int j = 0; j < total_width; j++) {
    freed[j] = false;
  }
  
  traverse(t->root, total_width, freed);

  return freed;
}

bool test_rbtree_malloc_randomized() {
  for (int k = 0; k < 100; k++) {
    unsigned seed = get_seed();
    srand(seed);

    uint64_t total_size = 100;
    rb_tree *t = create_chunk_file_rbtree(total_size);

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
  rb_tree *t = create_chunk_file_rbtree(total_size);
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
    rb_tree *t = create_chunk_file_rbtree(total_size);
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
    rb_tree *t = create_chunk_file_rbtree(total_size);

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


    chunk_aug_t *aug = (chunk_aug_t*)t->root->augmented;
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

bool test_read_write_inode() {
  int raid_levels[2] = {0, 5};
  for (int i = 0; i < 2; i++) {
    int raid_level = raid_levels[i];
    fs_handle *handle = init_filesystem(20, 2048, raid_level);

    uint64_t node_ptr = 100;
    inode *node1 = create_inode(5, 10, 100, 100);
    node1->ptr = 3;

    write_inode(handle, node1, node_ptr);

    inode *node2 = read_inode(handle, node_ptr);

    ASSERT(inodes_equal(node1, node2));
  }

  return true;
}

void print_storage(char **storage, int num_drives, int drive_size) {
  for (int k = 0; k < num_drives; k++) {
    for (int i = 0; i < drive_size; i++) {
      printf("%i ", storage[k][i]);
    } printf("\n");
  }
}

bool test_create_file() {
  int raid_levels[2] = {5};
  for (int i = 0; i < 2; i++) {
    fs_handle *handle = init_filesystem(NUM_BLOCKS, BLOCK_SIZE, raid_levels[i]);

    uint64_t node1_ptr = make_directory(handle, ROOT_NODE,  "testing1");
    uint64_t node2_ptr = make_directory(handle, node1_ptr, "testing2");
    uint64_t node3_ptr = make_directory(handle, ROOT_NODE,  "testing3");

    inode *node1 = read_inode(handle, node1_ptr);
    inode *node3 = read_inode(handle, node3_ptr);

    inode *root = read_inode(handle, ROOT_NODE);
    char *content = read_inode_content(handle, root);

    uint64_t *inode_numbers;
    char **subdirs = get_subdirectories(content, root->size, &inode_numbers);
    ASSERT(strcmp(subdirs[0], "testing1") == 0);
    ASSERT(strcmp(subdirs[1], "testing3") == 0);


    ASSERT(inodes_equal(read_inode(handle, inode_numbers[0]), node1), "Failed node comparison.");
    ASSERT(inodes_equal(read_inode(handle, inode_numbers[1]), node3), "Failed node comparison.");

    content = read_inode_content(handle, node1);
    subdirs = get_subdirectories(content, node1->size, &inode_numbers);
    ASSERT(strcmp(subdirs[0], "testing2") == 0);

    free(inode_numbers);
    free(content);
    free(subdirs);

    free(root);
    free(node1);
    free(node3);

    free_handle(handle);
  }

  return true;
}

bool test_find_inode() {
  int raid_levels[2] = {0, 5};
  for (int i = 0; i < 2; i++) {
    fs_handle *handle = init_filesystem(NUM_BLOCKS, BLOCK_SIZE, raid_levels[i]);

    uint64_t node1_ptr = make_directory(handle, ROOT_NODE,  "testing1");
    uint64_t node2_ptr = make_directory(handle, node1_ptr, "testing2");
    uint64_t node3_ptr = make_directory(handle, ROOT_NODE,  "testing3");
    char *success = "success";
    uint64_t node4_ptr = make_file(handle, node2_ptr,  "target", success, strlen(success));

    uint64_t node_ptr;
    inode *target = find_inode(handle, "/testing1/testing2/target", &node_ptr);
    char *content = read_inode_content(handle, target);

    ASSERT(strcmp(content, success) == 0);

    free_handle(handle);
  }

  return true;
}

bool test_virtual_ptrs() {
  // RAID-4
  {
    fs_handle *handle = init_filesystem(4, 32, 4);
    uint64_t s = 4;
    handle->stripe_size = s;

    int drives[24] =  {0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2};
    int stripes[24] = {0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7};

    for (uint64_t ptr = 0; ptr < 24*s; ptr++) {
      uint64_t drive, offset;
      get_drive_and_offset(handle, ptr, &drive, &offset);
      if (drive != drives[ptr/s]) {
        printf("Mismatched drive at ptr = %li. drive = %li, drives[ptr] = %li\n", ptr, drive, drives[ptr/s]);
        return false;
      }

      uint64_t stripe = offset / handle->stripe_size;
      if (stripe != stripes[ptr/s]) {
        printf("Mismatched stripe at ptr = %li. stripe = %li, stripes[ptr] = %li\n", ptr, stripe, stripes[ptr/s]);
        return false;
      }
    }

    free(handle);
  }

  // RAID-5
  {
    printf("RAID 5\n");
    fs_handle *handle = init_filesystem(4, 32, 5);
    uint64_t s = 4;
    handle->stripe_size = s;

    int drives[24] =  {0, 1, 2, 0, 1, 3, 
                       0, 2, 3, 1, 2, 3, 
                       0, 1, 2, 0, 1, 3, 
                       0, 2, 3, 1, 2, 3};

    int stripes[24] = {0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7};

    for (uint64_t ptr = 0; ptr < 24*s; ptr++) {
      uint64_t drive, offset;
      get_drive_and_offset(handle, ptr, &drive, &offset);
      if (drive != drives[ptr/s]) {
        printf("Mismatched drive at ptr = %li. drive = %li, drives[ptr] = %li\n", ptr/s, drive, drives[ptr/s]);
        return false;
      }

      uint64_t stripe = offset / handle->stripe_size;
      if (stripe != stripes[ptr/s]) {
        printf("Mismatched stripe at ptr = %li. stripe = %li, stripes[ptr] = %li\n", ptr/s, stripe, stripes[ptr/s]);
        return false;
      }
    }

    free(handle);
  }


  return true;
}

bool test_parity_chunk() {
  int raid_level = 5;
  fs_handle *handle = init_filesystem(NUM_BLOCKS, BLOCK_SIZE, raid_level);
  uint64_t size = 1000;
  uint64_t ptr  = handle->stripe_size * 20;
  char *content = malloc(size);
  for (uint64_t i = 0; i < size; i++) {
    content[i] = rand() % 32 + 92;
  }

  chunk_t hdr = {.ptr = ptr, .size = size};
  write_chunk(handle, hdr, content);
  free(content);

  uint64_t node_ptr = make_directory(handle, ROOT_NODE, "testing");

  uint64_t num_stripes = handle->drive_size / handle->stripe_size;
  for (uint64_t stripe = 0; stripe < num_stripes; stripe++) {
    check_parity(handle, stripe);
  }

  return true;
}

bool test_raid_repair_drive_basic() {
  for (int k = 0; k < 20; k++) {
    int raid_level = rand() % 2 + 4;
    printf("raid_level = %i\n", raid_level);
    fs_handle *handle = init_filesystem(30, 4000, raid_level);

    uint64_t buffer_size = rand() % 50000 + 5000;
    char *buffer = malloc(buffer_size);
    for (int i = 0; i < buffer_size; i++) {
      buffer[i] = rand() % 32 + 92;
    }

    uint64_t ptr = rand() % 50000;

    chunk_t hdr = {.ptr = ptr, .size = buffer_size};

    write_chunk(handle, hdr, buffer);

    uint64_t failed_drive = rand() % handle->num_drives;

    char *buffer_after = malloc(buffer_size);
    simulate_drive_failure(handle, failed_drive);
    read_chunk(handle, hdr, buffer_after, 0);

    bool failed = false;
    for (int i = 0; i < buffer_size; i++) {
      if (buffer[i] != buffer_after[i]) {
        failed = true;
        break;
      }
    }

    if (!failed) {
      printf("Simulating drive failure did not corrupt data.\n");
      return false;
    }

    repair_failed_drive(handle, failed_drive);
    read_chunk(handle, hdr, buffer_after, 0);
    for (int i = 0; i < buffer_size; i++) {
      if (buffer[i] != buffer_after[i]) {
        printf("Corruption at site %li\n", i);
        return false;
      }
    }
  }
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
  ADD_TEST(test_thread_pool);

  // Storage IO tests
  ADD_TEST(test_write_chunk_basic);
  ADD_TEST(test_read_chunk_basic);
  ADD_TEST(test_read_chunk_with_offset);
  ADD_TEST(test_write_then_read_roundtrip);
  ADD_TEST(test_write_to_chunk_basic);
  ADD_TEST(test_write_to_chunk_middle);
  ADD_TEST(test_write_to_chunk_exact_end);
  ADD_TEST(test_write_to_chunk_past_end);
  ADD_TEST(test_write_to_data_multidrive);
  ADD_TEST(test_read_data_multidrive);
  
  // rbtree basics
  ADD_TEST(test_rbtree_basic);
  ADD_TEST(test_rbtree_sorted_order);
  ADD_TEST(test_rbtree_stress);
  ADD_TEST(test_rbtree_delete_randomized);
  ADD_TEST(test_rbtree_successor_predecessor);
  ADD_TEST(test_rbtree_augmented_max_size);
  ADD_TEST(test_rbtree_serialize);

  // rbtree filesystem allocation/free
  ADD_TEST(test_rbtree_malloc_randomized);
  ADD_TEST(test_rbtree_mfree_basic);
  ADD_TEST(test_rbtree_mfree_randomized);
  ADD_TEST(test_rbtree_free_ptr);

  // Directory traversal
  ADD_TEST(test_get_subdirectories);
  ADD_TEST(test_read_write_inode);
  ADD_TEST(test_create_file);
  ADD_TEST(test_find_inode);

  // RAID tests
  ADD_TEST(test_virtual_ptrs);
  ADD_TEST(test_parity_chunk);
  ADD_TEST(test_raid_repair_drive_basic);

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
