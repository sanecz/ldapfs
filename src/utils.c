#include "fuse_ldap.h"

int hashpjw(char *s) {
  char* p;
  unsigned int h, g;

   h = 0;
  for(p = s; *p != '\0'; p++){
    h = (h<<4) + *p;
    if ((g = h&0xF0000000)) {
      h ^= g >> 24;
      h ^= g;
    }
  }
  return h;
}

char* is_dn_exist(const char* path) {
  LDAPMessage* msg = NULL;
  LDAPMessage* entry = NULL;
  char* dn;

  dn = path_to_dn(path, "ou=");
  ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", NULL, 0, &msg);
  entry = ldap_first_entry(ld, msg);
  if (!entry) {
    ldap_msgfree(msg);
    free(dn);
    dn = path_to_dn(path, "cn=");
    ldap_search_s(ld, dn, LDAP_SCOPE_BASE, "(ObjectClass=*)", NULL, 0, &msg);
    if (!(entry = ldap_first_entry(ld, msg))) {
      ldap_msgfree(msg);
      free(dn);
      return NULL;
    }
  }
  ldap_msgfree(msg);
  return dn;
}

int modify_attr(const char* path, int action, char* attr, char *val) {
  char* dn;
  LDAPMod* mods[2];

  if (!(dn = is_dn_exist(path)))
    return -ENOENT;
  
  mods[0] = malloc(sizeof(LDAPMod));
  mods[0]->mod_op = action;
  mods[0]->mod_type = attr;
  mods[0]->mod_values = malloc(sizeof(char *) * 2);
  mods[0]->mod_values[0] = val;
  mods[0]->mod_values[1] = NULL;
  mods[1] = NULL;
  
  ldap_modify_s(ld, dn, mods);
  free(mods[0]->mod_values);
  free(mods[0]);
  free(dn);

  return 0;
}

char *path_to_dn(const char *path, char *type) {
  size_t i, j, save;
  char *name;
  char *dn = NULL;
  char **tab = NULL;
  char *token = NULL;
  
  name = strdup(path);
  for (i = 0, j = 0; name[i]; i++)
    j = (name[i] == '/' && i != (strlen(name) - 1)) ? j + 1 : j;
  if (!(tab = calloc(j + 1, sizeof(char *)))) {
    free(name);
    return NULL;
  }
  save = j + 1;
  token = strtok(name, "/");
  for(i = 0; token; token = strtok(NULL, "/"), i++)
    tab[i] = strdup(token);
  if (!(dn = calloc(sizeof(BASE_DN) + (j * sizeof("ou=,")) + strlen(path) + 1, sizeof(char)))) {
    for (i = 0; tab[i]; i++)
      free(tab[i]);
    free(name);
    free(tab);
    return NULL;
  }
  while (j > 0) {
    j--;
    if (!strcmp(dn, ""))
      strcpy(dn, type);
    else
      strcat(dn, "ou=");
    strcat(dn, tab[j]);
    strcat(dn, ",");
  }
  strcat(dn, BASE_DN);
  for (i = 0; i < save; i++)
    free(tab[i]);
  free(tab);
  free(name);
  return dn;    
}

LDAP *auth_fldap(void) {
  LDAP *ld;
  int rc;
  const static int version = 3;

  if (ldap_initialize(&ld, LDAP_SRV))
    return NULL;
  if ((rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, (void *)&version)) != LDAP_SUCCESS)
      return NULL;
  if ((rc = ldap_simple_bind_s(ld, BIND_DN, BIND_PW)) != LDAP_SUCCESS)
    return NULL;

  return ld;
}

int create(const char* path, mode_t mode, size_t size, int flag, void* rdev) {
  char* dn;
  LDAPMod* mods[13];
  char buf[32][13];
  int i, j, save;

  if ((dn = is_dn_exist(path))) {
    free(dn);
    return -EEXIST;
  }
  
  for (i = 0; i < 11; i++) {
    mods[i] = calloc(1, sizeof(LDAPMod));
    mods[i]->mod_values = calloc(2, sizeof(char *));
    mods[i]->mod_values[1] = NULL;
  }
  
  for (j = 0; path[j]; j++) {
    if (path[j] == '/')
      save = j;
  }

  mods[0]->mod_type = "statime";
  mods[0]->mod_values[0] = "0";

  mods[1]->mod_type = "stblocks";
  snprintf(buf[0], 32, "%"PRIu64, size / 512);
  mods[1]->mod_values[0] = buf[0];

  mods[2]->mod_type = "stblksize";
  mods[2]->mod_values[0] = "512";

  mods[3]->mod_type = "stsize";
  snprintf(buf[1], 32, "%"PRIu64, size);
  mods[3]->mod_values[0] = buf[1];

  mods[4]->mod_type = "strdev";
  snprintf(buf[2], 32, "%"PRIu64, (dev_t)rdev);
  mods[4]->mod_values[0] = buf[2];
  mods[5]->mod_type = "stnlink";
  mods[5]->mod_values[0] = "2";

  mods[6]->mod_type = "stmode";
  snprintf(buf[3], 32, "%"PRIu32, mode);
  mods[6]->mod_values[0] = buf[3];

  mods[7]->mod_type = "stuid";
  snprintf(buf[4], 32, "%"PRIi32, getuid());
  mods[7]->mod_values[0] = buf[4];

  mods[8]->mod_type = "stgid";
  snprintf(buf[5], 32, "%"PRIi32, getuid());
  mods[8]->mod_values[0] = buf[5];
  
  if (flag == S_IFDIR) {
    mods[9]->mod_type = "ou";
    dn = path_to_dn(path, "ou=");
  } else {
    mods[9]->mod_type = "sn";
    dn = path_to_dn(path, "cn=");
  }

  mods[9]->mod_values[0] = (char *)&path[save + 1];
  mods[10]->mod_type = "filename";
  mods[10]->mod_values[0] = (char *)&path[save + 1];
  mods[11] = calloc(1, sizeof(LDAPMod));
  mods[11]->mod_type = "objectClass";
  mods[11]->mod_values = calloc(3, sizeof(char *));
  mods[11]->mod_values[0] = "ldapfsFile";
  if (flag == S_IFDIR)
    mods[11]->mod_values[1] = "organizationalUnit";
  else
    mods[11]->mod_values[1] = "organizationalPerson";
  mods[12] = NULL;

  ldap_add_s(ld, dn, mods);
  for (i = 0; i < 12; i++) {
    free(mods[i]->mod_values);
    free(mods[i]);
  }

  free(dn);
  return 0;
}
