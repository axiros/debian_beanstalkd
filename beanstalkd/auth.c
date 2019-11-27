#include <sys/random.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include "dat.h"

#include <apr-1.0/apr_lib.h>
#include <apr-1.0/apr_pools.h>
#include <apr-1.0/apr_strings.h>
#include <apr-1.0/apr_tables.h>
#include <apr-1.0/apr_escape.h>
#include <apr-1.0/apr_md5.h>

#define CONSTSTRLEN(m) (sizeof(m) - 1)

#define MSG_BAD_FORMAT "BAD_FORMAT\r\n"
#define MSG_AUTH_MISSING_AUTH1 "MISSING_AUTH1\r\n"
#define MSG_AUTH_NOT_AUTHZ "NOT_AUTHORIZED\r\n"
#define MSG_AUTH_USER_NOT_FOUND "AUTH_USER_NOT_FOUND\r\n"
#define MSG_AUTH_NONCE "NONCE %s\r\n"
#define MSG_AUTH_GRANTED "AUTH_GRANTED\r\n"
#define MSG_AUTH_FAILED "AUTH_FAILED\r\n"

static const char MATCH_USER[] = "^[[:space:]]*([^:]*)::([[:alnum:]]*)[[:space:]]*$";

typedef struct {
    char* username;
    char* pw_hash;
} user_t;


static struct {
    apr_pool_t* pool;
    apr_array_header_t* users;
} auth_store = {NULL, NULL};


static char*
as_upper(char* out) {
    for (int i=0; i < strlen(out); ++i) {
        out[i] = apr_toupper(out[i]);
    }

    return out;
}

void
auth_read_users_files(const char* path)
{
    regex_t reg;
    regmatch_t pmatch[3];

    FILE* fp = NULL;
    char* line = NULL;
    size_t line_len = 0;

    if (apr_initialize() != APR_SUCCESS) {
        fprintf(stderr, "apr_initialize failed\n");
        exit(1);
    }

    if (apr_pool_create(&auth_store.pool, NULL) != APR_SUCCESS) {
        fprintf(stderr, "Cannot allocate auth_storage pool\n");
        exit(1);
    }

    auth_store.users = apr_array_make(auth_store.pool, 0, sizeof(user_t));
    if (auth_store.users == NULL) {
        fprintf(stderr, "Cannot allocate array for users\n");
        exit(1);
    }

    if (regcomp(&reg, MATCH_USER, REG_NEWLINE | REG_EXTENDED) != 0) {
        fprintf(stderr, "Cannot compile regex to parse auth file\n");
        exit(1);
    }

    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stderr, "Cannot open auth file: %s\n", path);
        exit(1);
    }

    while (getline(&line, &line_len, fp) != -1) {
        if (regexec(&reg, line, 3, pmatch, 0) != 0) {
            continue;
        }

        user_t* user = (user_t*) apr_array_push(auth_store.users);

        user->username = apr_pstrndup(
            auth_store.pool,
            line + pmatch[1].rm_so,
            pmatch[1].rm_eo - pmatch[1].rm_so);

        user->pw_hash = apr_pstrndup(
            auth_store.pool,
            line + pmatch[2].rm_so,
            pmatch[2].rm_eo - pmatch[2].rm_so);

        as_upper(user->pw_hash);
    }

    free(line);
    fclose(fp);
    regfree(&reg);
}

static const user_t*
auth_store_find(const char* username)
{
    for (int i=0; i < auth_store.users->nelts; ++i) {
        const user_t* user = &APR_ARRAY_IDX(auth_store.users, i, user_t);
        if (strcmp(user->username, username) == 0) {
            return user;
        }
    }

    return NULL;
}

static void
generate_nonce(char* dst)
{
    char tmp[AUTH_NONCE_SIZE / 2];

    if (getrandom(tmp, sizeof(tmp), 0) < sizeof(tmp)) {
        for (int i=0; i < sizeof(tmp); ++i) {
            tmp[i] = random();
        }
    }

    apr_escape_hex(dst, tmp, sizeof(tmp), 0, NULL);
    as_upper(dst);
}


static char*
do_auth1(Conn* c) {
    if (strlen(c->cmd) <= CONSTSTRLEN(CMD_AUTH1)) {
        return MSG_BAD_FORMAT;
    }

    const user_t* user = auth_store_find(c->cmd + CONSTSTRLEN(CMD_AUTH1));
    if (user == NULL) {
        return MSG_AUTH_USER_NOT_FOUND;
    }

    c->auth.username = user->username;
    c->auth.pw_hash = user->pw_hash;

    generate_nonce(c->auth.nonce);
    snprintf(c->reply_buf, LINE_BUF_SIZE, MSG_AUTH_NONCE, c->auth.nonce);
    return c->reply_buf;
}

static void
do_md5(char dst[], const char* src, size_t size)
{
    unsigned char digest[APR_MD5_DIGESTSIZE];
    apr_md5(digest, src, size);
    apr_escape_hex(dst, digest, APR_MD5_DIGESTSIZE, 0, NULL);
    as_upper(dst);
}


static char*
do_auth2(Conn* c)
{
    if (c->auth.username == NULL) {
        return MSG_AUTH_MISSING_AUTH1;
    }

    if (c->auth.pw_hash == NULL) {
        return MSG_AUTH_MISSING_AUTH1;
    }

    /* The code does the following: md5(pw_hash:nonce) == auth2. */

    size_t signature_size = strlen(c->auth.pw_hash) + AUTH_NONCE_SIZE + 1;
    char signature[signature_size + 1];
    sprintf(signature, "%s:%s", c->auth.pw_hash, c->auth.nonce);

    char digest[(APR_MD5_DIGESTSIZE * 2) + 1];
    do_md5(digest, signature, signature_size);

    const char* cmd_digest = c->cmd + CONSTSTRLEN(CMD_AUTH2);
    c->auth.authenticated = (strcmp(digest, cmd_digest) == 0);

    if (c->auth.authenticated) {
        return MSG_AUTH_GRANTED;
    } else {
        return MSG_AUTH_FAILED;
    }
}

char*
authenticate(Conn* c, int op_type) {
    /* Authentication is not enabled. */
    if (auth_store.users == NULL) {
        return NULL;
    }

    /* Authentication is not enabled. */
    if (auth_store.users->nelts == 0) {
        return NULL;
    }

    /* In case the connection has already been authenticated. */
    if (c->auth.authenticated == 1) {
        return NULL;
    }

    switch (op_type) {
        case OP_UNKNOWN:
            return NULL;

        case OP_QUIT:
            return NULL;

        case OP_AUTH1:
            return do_auth1(c);

        case OP_AUTH2:
            return do_auth2(c);

        default:
            return MSG_AUTH_NOT_AUTHZ;
    }
}
