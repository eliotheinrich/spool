#define FUSE_USE_VERSION 36

#include <stdlib.h>
#include <errno.h>
#include <fuse3/fuse.h>
#include <string.h>
#include <stdio.h>

#include "node.h"

char **storage;
rb_tree *t;

static int fs_readdir(const char *path, void *data, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  filler(data, ".", NULL, 0, 0);
  filler(data, "..", NULL, 0, 0);

  char *content = read_inode_content(storage, node);
  uint64_t *inode_numbers = NULL;
  char **subdirs = get_subdirectories(content, node->size, &inode_numbers);

  if (subdirs) {
    char **p = subdirs;
    while (*p) {
      filler(data, *p, NULL, 0, 0);
      p++;
    }
  } 

  free(node);
  free(content);
  free(inode_numbers);
  free(subdirs);

  return 0;
}

static int fs_mkdir(const char *path, mode_t mode) {
  char *rest;
  char *filename = path_last(path, &rest);
  
  uint64_t parent_ptr;
  inode *parent = find_inode(storage, rest, &parent_ptr);
  if (!parent || !(parent->mode & FILETYPE_DIR)) {
    free(parent);
    free(filename);
    return -ENOENT;
  }

  uint64_t node_ptr = make_directory(t, storage, parent_ptr, filename);

  free(parent);
  free(filename);

  return 0;
}

static int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  if (node->mode & FILETYPE_DIR) {
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = node->link_count;
  } else {
    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_size = node->size;
  }

  free(node);
	return 0;
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);

  if (!node) {
    return -ENOENT;
  }

  if (node->mode & FILETYPE_DIR) {
    return -EISDIR;
  }

  size_t node_size = node->size;
  size_t to_write = 0;
  size_t append_size = 0;

  if (offset < node_size) {
    // bytes that will overwrite existing data
    to_write = (size <= node_size - offset) ? size : node_size - offset;
  }

  if (offset + size > node_size) {
    // bytes that need to be appended
    append_size = offset + size - node_size;
  }

  // overwrite existing data
  if (to_write > 0) {
    write_to_data(storage, node->ptr, to_write, buf, offset);
  }

  // append new data
  if (append_size > 0) {
    append_to_inode(t, storage, buf + to_write, append_size, node_ptr);
  }

  return size;

}

static int fs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  if (node->mode & FILETYPE_DIR) {
    return -EISDIR;
  }

  if ((size_t)size < node->size) {
    // truncate file: remove bytes from the end
    //truncate_inode(storage, node_ptr, size);  // implement this
  } else if ((size_t)size > node->size) {
    // expand file: append zeros
    append_to_inode(t, storage, NULL, size - node->size, node_ptr);
  }

  node->size = size;
  write_inode(storage, node, node_ptr);
  return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  if ((fi->flags & O_ACCMODE) != O_RDONLY && (node->mode & FILETYPE_FILE) == 0) {
    free(node);
    return -EACCES;
  }

  free(node);
  return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node || !(node->mode & FILETYPE_FILE)) {
    return -ENOENT;
  }

  if (offset >= node->size) {
    return 0;
  }

  if (offset + size > node->size) {
    size = node->size - offset;
  }

  read_data_offset(storage, node->ptr, node->size, buf, (uint64_t) offset);
  return size;
}

static int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  char *rest;
  char *filename = path_last(path, &rest);
  
  uint64_t parent_ptr;
  inode *parent = find_inode(storage, rest, &parent_ptr);
  if (!parent || !(parent->mode & FILETYPE_DIR)) {
    free(filename);
    free(parent);
    return -ENOENT;
  }
  free(parent);

  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (node) {
    free(filename);
    free(node);
    return -EEXIST;
  }

  node_ptr = make_file(t, storage, parent_ptr, filename, NULL, 0);

  free(filename);
  return 0;
}

static int fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  if (!S_ISREG(mode)) {
    return -EINVAL;
  }

  return fs_create(path, mode, NULL);
}

static int fs_unlink(const char *path) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    free(node);
    return -ENOENT;
  }

  if (node->mode & FILETYPE_ROOT) {
    free(node);
    return -1;
  }

  if (!(node->mode & FILETYPE_DIR)) {
    free(node);
    return -EISDIR;
  }

  free(node);

  char *rest;
  char *filename = path_last(path, rest);

  uint64_t parent_ptr;
  inode *parent = find_inode(storage, rest, &parent_ptr);

  if (!parent) {
    return -1;
  }

  char *parent_content = read_inode_content(storage, parent);
  char *removed;
  size_t out_size;
  remove_element(parent_content, parent->size, filename, &removed, &out_size);
  replace_inode_content(storage, t, parent_ptr, removed, out_size);
  remove_directory(storage, t, node_ptr);

  free(parent);
  free(parent_content);
  free(removed);
  free(filename); 
  free(rest);

  return 0;
}

static int fs_rmdir(const char *path) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  if (!(node->mode & FILETYPE_DIR)) {
    free(node);
    return -ENOTDIR; 
  }

  if (node->size != 0) {
    free(node);
    return -ENOTEMPTY;
  }

  fs_unlink(path);

  free(node);
  return 0; 
}

static int fs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
  uint64_t node_ptr;
  inode *node = find_inode(storage, path, &node_ptr);
  if (!node) {
    return -ENOENT;
  }

  node->atime = tv[0].tv_sec;
  node->mtime = tv[1].tv_sec;

  node->ctime = time(NULL);

  write_inode(storage, node, node_ptr);

  free(node);

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
  .rmdir = fs_rmdir,
  .unlink = fs_unlink,
  .utimens = fs_utimens,
};

int main(int argc, char **argv) {
  storage = init_filesystem(&t);

  int result = fuse_main(argc, argv, &fsops, NULL);

  rb_tree(t);
  free(storage);
  return result;
}
