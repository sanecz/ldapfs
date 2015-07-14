#ifndef __FUSE_LDAP_H__

#define __FUSE_LDAP_H__
#define _GNU_SOURCE
#define LDAP_DEPRECATED 1
#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ldap.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>

#define MODE_HASH 128664997
#define NLINK_HASH 179646523
#define UID_HASH 8043508
#define GID_HASH 8039924
#define RDEV_HASH 128682694
#define SIZE_HASH 128688389
#define BLKZ_HASH 154336165
#define BLOCK_HASH 177430403
#define ATIME_HASH 178827333
#define MTIME_HASH 154614512
#define CTIME_HASH 138438848
#define LDAP_SRV "ldap://127.0.0.1:389"
#define BASE_DN "dc=root,dc=ldap"
#define BIND_DN "cn=admin,dc=root,dc=ldap"
#define BIND_PW "tomatoes and potatoes"

extern LDAP* ld;

LDAP* auth_fldap(void);
char* path_to_dn(const char *path, char *type);
char* is_dn_exist(const char* path);
int modify_attr(const char* path, int action, char* attr, char *val);
int hashpjw(char* s);
int create(const char* path, mode_t mode, size_t size, int flag, void* rdev);

#endif
