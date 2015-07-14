#include "fuse_ldap.h"

LDAP* ld = NULL;

static int fldap_getattr(const char* path, struct stat* stbuf) {
  static char* attrs[] = {"stmode", "stnlink", "stuid", "stgid", "strdev", "stblksize", "stsize", "stblocks", "statime", "createtimest\
amp", "modifytimestamp", NULL};
  int res = 0;
  struct tm tm = {0};
  char* dn;
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  BerElement* ber = NULL;
  char** vals;
  char* attr;

  memset(stbuf, 0, sizeof(struct stat));

  dn = path_to_dn(path, "ou=");
  ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", attrs, 0, &msg);
  entry = ldap_first_entry(ld, msg);
  if (!entry) {
    ldap_msgfree(msg);
    free(dn);
    dn = path_to_dn(path, "cn=");
    ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", attrs, 0, &msg);
    if (!(entry = ldap_first_entry(ld, msg))) {
      ldap_msgfree(msg);
      free(dn);
      return -ENOENT;
    }
  }

  entry = ldap_first_entry(ld, msg);
  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
  } else if (entry == NULL) {
    res = -ENOENT;
  } else {
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
      if ((vals = ldap_get_values(ld, entry, attr)) != NULL)  {
	switch (hashpjw(attr)) {
	case MODE_HASH: stbuf->st_mode = atoi(vals[0]); break;
	case NLINK_HASH: stbuf->st_nlink = atoi(vals[0]); break;
	case UID_HASH: stbuf->st_uid = atoi(vals[0]); break;
	case GID_HASH: stbuf->st_gid = atoi(vals[0]); break;
	case RDEV_HASH: stbuf->st_rdev = atoi(vals[0]); break;
	case SIZE_HASH: stbuf->st_size = atoi(vals[0]); break;
	case BLKZ_HASH: stbuf->st_blksize = atoi(vals[0]); break;
	case BLOCK_HASH: stbuf->st_blocks = atoi(vals[0]); break;
	case ATIME_HASH: stbuf->st_atime = atoi(vals[0]); break;
	case CTIME_HASH: strptime(vals[0], "%Y%m%d%H%M%SZ", &tm); stbuf->st_ctime = mktime(&tm); break;
	case MTIME_HASH: strptime(vals[0], "%Y%m%d%H%M%SZ", &tm); stbuf->st_mtime = mktime(&tm); break;

	}
	ldap_value_free(vals);
      }
      ldap_memfree(attr);
    }
    ber_free(ber, 0);
  }
  ldap_msgfree(msg);
  free(dn);
  return res;
}

static int fldap_access(const char* path, int mask) {
  struct fuse_context* context;
  struct stat* stbuf;

  /* Not implemented, memo */
  stbuf = calloc(1, sizeof(struct stat));
  context = fuse_get_context();
  fldap_getattr(path, stbuf);
  free(stbuf);
  return 0;
}

static int fldap_readlink(const char* path, char* buf, size_t size) {
  static char* attrs[] = {"description", NULL};
  char* dn;
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  BerElement* ber = NULL;
  char** vals;
  char* attr;
  
  if ((dn = is_dn_exist(path))) {
    ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", attrs, 0, &msg);
    if ((entry = ldap_first_entry(ld, msg))) {
      for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
	if ((vals = ldap_get_values(ld, entry, attr)) != NULL)  {
	  if (!strcmp("description", attr))
	    strncpy(buf, vals[0], size);
	  ldap_value_free(vals);
	}
	ldap_memfree(attr);
      }
      ber_free(ber, 0);
    }
    ldap_msgfree(msg);
  }
  free(dn);
  return 0;
}

static int fldap_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {
  static char* attrs[] = {"filename", NULL};
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  BerElement* ber = NULL;
  char* dn;
  char** vals;
  char* attr;

  /* The path returned should look like that "/path/to/the/folder".
   *  After the split, we should have something like that:
   *  ou=folder,ou=the,ou=to,ou=path,dc=example,dc=com
   *  This is the dn of the folder.
   */

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);
  dn = path_to_dn(path, "ou=");
  if (ldap_search_s(ld, dn, LDAP_SCOPE_ONE, "(ObjectClass=*)", attrs, 0, &msg) != LDAP_SUCCESS) {
    return -ENOENT;
    free(dn);
  }
  entry = ldap_first_entry(ld, msg);
  if (!entry) {
    ldap_msgfree(msg);
    free(dn);
    return 0;
  }

  for (entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
    for( attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
      if ((vals = ldap_get_values(ld, entry, attr)) != NULL)  {
	if (!strcmp("filename", attr))
	  filler(buf, vals[0], NULL, 0);
	ldap_value_free(vals);
      }
      ldap_memfree(attr);
    }
    ber_free(ber,0);
  }
  ldap_msgfree(msg);

  free(dn);
  return 0;
}

static int fldap_mknod(const char* path, mode_t mode, dev_t rdev) {
  return create(path, mode, 4096, mode & 0xffff000, (void *)rdev);
}

static int fldap_mkdir(const char* path, mode_t mode) {
  return create(path, mode ^ S_IFDIR, 4096, S_IFDIR, 0);
}

static int fldap_create(const char* path, mode_t mode, struct fuse_file_info* info) {
  return create(path, mode, 0, S_IFREG, 0);
}

static int fldap_rm(const char* path) {
  char* dn;

  if (!(dn = is_dn_exist(path)))
    return -ENOENT;
  if (ldap_delete_s(ld, dn) != LDAP_SUCCESS) {
    free(dn);
    return -EIO;
  }
  free(dn);

  return 0;
}

static int fldap_symlink(const char* from, const char* to) {
  char* dn_from;
  char* dn_to;

  dn_from = is_dn_exist(from);
  dn_to = path_to_dn(to, "cn=");
  
  create(to, (mode_t)0777 ^ S_IFLNK, 4, S_IFLNK, 0);
  if (!strcmp(dn_from, BASE_DN))
    modify_attr(to, LDAP_MOD_ADD, "description", (char *)from);
  else
    modify_attr(to, LDAP_MOD_ADD, "description", dn_from);
  free(dn_from);
  free(dn_to);
  return 0;
}

static int fldap_rename(const char* from, const char* to) {
  return 0;
}

static int fldap_chmod(const char* path, mode_t mode) {
  char buf[32];

  snprintf(buf, 32, "%"PRIi32, mode);
  return modify_attr(path, LDAP_MOD_REPLACE, "stmode", buf);
}

static int fldap_chown(const char* path, uid_t uid, gid_t gid) {
  char buf[2][32];

  snprintf(buf[0], 32, "%"PRIi32, uid);
  if (modify_attr(path, LDAP_MOD_REPLACE, "stuid", buf[0]) != 0)
    return -ENOENT;
  snprintf(buf[1], 32, "%"PRIi32, gid);
  return modify_attr(path, LDAP_MOD_REPLACE, "stgid", buf[1]);
}

static int fldap_truncate(const char* path, off_t size) {
  return 0;
}

static int fldap_utimens(const char* path, const struct timespec ts[2]) {
  return 0;
}

static int fldap_open(const char* path, struct fuse_file_info* fi) {
  return 0;

}

static int fldap_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
  static char* attrs[] = {"description", NULL};
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  BerElement* ber = NULL;
  char* dn;
  char** vals;
  char* attr;

  dn = path_to_dn(path, "cn=");
  ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", attrs, 0, &msg);
  entry = ldap_first_entry(ld, msg);

  if (!entry) {
    ldap_msgfree(msg);
    free(dn);
    return -ENOENT;
  }

  for (entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
      if (!strcmp(attr, "description") && ((vals = ldap_get_values(ld, entry, attr)) != NULL))  {
	strncpy(buf, vals[0] + offset, size);
	ldap_value_free(vals);
      }
      ldap_memfree(attr);
    }
    ber_free(ber,0);
  }
  ldap_msgfree(msg);
  free(dn);
  return strlen(buf);
}

static int fldap_write(const char* path, const char* data, size_t size, off_t offset, struct fuse_file_info* fi) {
  static char* attrs[] = {"description", NULL};
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  BerElement* ber = NULL;
  char* buf = NULL;
  char strsize[32];
  char* dn;
  char** vals;
  char* attr;

  dn = path_to_dn(path, "cn=");
  ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", attrs, 0, &msg);
  entry = ldap_first_entry(ld, msg);

  if (!entry) {
    ldap_msgfree(msg);
    free(dn);
    return -ENOENT;
  }
  for (entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
      if (!strcmp(attr, "description") && ((vals = ldap_get_values(ld, entry, attr)) != NULL))  {
	buf = calloc(strlen(vals[0]) + size + 1, sizeof(char));
	strncpy(buf, vals[0], offset);
	strncat(buf, data, size);
	ldap_value_free(vals);
      }
      ldap_memfree(attr);
    }
    ber_free(ber, 0);
  }
  ldap_msgfree(msg);
  if (!buf) {
    buf = calloc(size + 1, sizeof(char));
    strncpy(buf, data, size);
  }
  snprintf(strsize, 32, "%"PRIi32, (int)strlen(buf));
  modify_attr(path, LDAP_MOD_REPLACE, "description", buf);
  modify_attr(path, LDAP_MOD_REPLACE, "stsize", strsize);
  free(dn);
  free(buf);
  return size;
}

static int fldap_statfs(const char* path, struct statvfs* stbuf) {
  return 0;
}

static int fldap_release(const char* path, struct fuse_file_info* fi) {
  return 0;
}

static int fldap_sync(const char* path, int isdatasync, struct fuse_file_info *fi) {
  return 0;
}

static struct fuse_operations fldap_oper = {
  .getattr = fldap_getattr,
  .access = fldap_access,
  .readlink = fldap_readlink,
  .readdir = fldap_readdir,
  .mknod = fldap_mknod,
  .mkdir = fldap_mkdir,
  .symlink = fldap_symlink,
  .unlink = fldap_rm,
  .rmdir = fldap_rm,
  .create = fldap_create,
  .rename = fldap_rename,
  .link = fldap_symlink,
  .chmod = fldap_chmod,
  .chown = fldap_chown,
  .truncate = fldap_truncate,
  .utimens = fldap_utimens,
  .open = fldap_open,
  .read = fldap_read,
  .write = fldap_write,
  .statfs = fldap_statfs,
  .release = fldap_release,
  .fsync = fldap_sync,
};

int main(int ac, char** av) {
  if (!(ld = auth_fldap()))
    return 255;
  openlog("slog", LOG_PID|LOG_CONS, LOG_USER);

  fuse_main(ac, av, &fldap_oper, NULL);
  ldap_unbind_s(ld);

  closelog();
  return 0;
}

