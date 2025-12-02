#define FUSE_USE_VERSION 36

#include <stdlib.h>
#include <errno.h>
#include <fuse3/fuse.h>
#include <string.h>
#include <stdio.h>

#include "node.h"

#define FILE_SIZE 1024
#define METADATA_SIZE 128
static char file_contents[FILE_SIZE];

Node* root;

static int fs_readdir(const char *path, void *data, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi,
	enum fuse_readdir_flags flags) {

  Node *dir = find_node(root, path);
  if (!dir || dir->type != FILETYPE_DIR) {
    return -ENOENT;
  }

	filler(data, ".", NULL, 0, 0);
	filler(data, "..", NULL, 0, 0);
  for (int i = 0; i < dir->n_children; i++) {
    Node *child = dir->children[i];
    filler(data, child->name, NULL, 0, 0);
  }

	return 0;
}

static int fs_mkdir(const char *path, mode_t mode) {
  char *parent_path, *dirname;
  split_parent(path, &parent_path, &dirname);

  Node *parent = find_node(root, parent_path);
  if (!parent) {
    free(dirname);
    free(parent_path);
    return -ENOENT;
  }

  Node *child = create_node(dirname, NULL, FILETYPE_DIR);
  add_child(parent, child);

  free(dirname);
  free(parent_path);
  return 0;
}

static int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
  if (strcmp(path, "/") == 0) {
		st->st_mode = S_IFDIR | 0755;  // directory
		st->st_nlink = 2;
  } else {
    Node *node = find_node(root, path);
    if (!node) {
      printf("On getattr(%s), did not find the node.\n", path);
      return -ENOENT;
    }

    if (node->type == FILETYPE_DIR)  {
      st->st_mode = S_IFDIR | 0755;  // directory
      st->st_nlink = 2;
      printf("On getattr(%s), found a directory.\n", path);
    } else {
      st->st_mode = S_IFREG | 0644;  // regular file
      st->st_nlink = 1;
      st->st_size = node->size;

      printf("On getattr(%s), found a file.\n", path);
    }
  }

	return 0;
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  Node *node = find_node(root, path);
  if (!node) {
    return -ENOENT;
  }

  if (node->type == FILETYPE_DIR) {
    return -EISDIR;
  }

  
  size_t required = offset + size;
  printf("required = %i, offset = %i, size = %i\n", required, offset, size);
  printf("buf = %s\n", buf);
  if (required > node->size) {
    char *new_content = realloc(node->content, required);

    node->content = new_content;
    node->size = required;
  }

  memcpy(node->content + offset, buf, size);

  return size;
}

static int fs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
  if (strcmp(path, "/file") != 0)
    return -ENOENT;

  // simple: zero out if truncated smaller
  if (size < FILE_SIZE) {
    memset(file_contents + size, 0, FILE_SIZE - size);
  }

  return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi) {
  // Allow writing
  return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  Node *node = find_node(root, path);
  if (!node || node->type != FILETYPE_FILE) {
    return -ENOENT;
  }

  if (offset >= node->size) {
    return 0;
  }

  if (offset + size > node->size) {
    size = node->size - offset;
  }

  memcpy(buf, node->content + offset, size);
  return size;
}

static int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  char *parent_path, *name;
  split_parent(path, &parent_path, &name);

  Node *parent = find_node(root, parent_path);
  printf("Found parent directory:\n");
  print_tree(parent);
  if (!parent || parent->type != FILETYPE_DIR) {
    free(parent_path);
    free(name);
    printf("Parent does not exist.\n");
    return -ENOENT;
  }

  if (find_node(parent, name)) {
    free(parent_path);
    free(name);
    printf("File already exists.\n");
    return -EEXIST;
  }

  Node *child = create_node(name, NULL, FILETYPE_FILE);
  add_child(parent, child);

  free(parent_path);
  free(name);
  printf("Exiting normal way.\n");
  return 0;
}

static int fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  if (!S_ISREG(mode)) {
    return -EINVAL;
  }

  return fs_create(path, mode, NULL);
}

// TODO add proper timestamp support
static int fs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
  Node *node = find_node(root, path);
  if (!node) {
    return -ENOENT;
  }

  return 0;
}

struct fuse_operations fsops = {
  .readdir = fs_readdir,
  .getattr = fs_getattr,
  .open = fs_open,
  .read = fs_read,
  .write = fs_write,
  .truncate = fs_truncate,
  .mkdir = fs_mkdir,
  .mknod = fs_mknod,
  .create = fs_create,
  .utimens = fs_utimens,
};

int main(int argc, char **argv) {
  int backing_fd = open("backing.img", O_RDWR | O_CREAT, 0644);
  root = load_filesystem(backing_fd);

  //ftruncate(backing_fd, 1024); // allocate 1 KB for example
  int result = fuse_main(argc, argv, &fsops, NULL);
  free_tree(root);
  return result;
}
