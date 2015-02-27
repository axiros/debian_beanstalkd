/*
 * auth.c
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#include "auth.h"
#include "prot.h"
#include "util.h"
#include "md5.h"

#include <stdio.h>
#include <ctype.h>
/* creds repo */
struct AUTH_RECORD_LIST *authStorage = NULL;
static int use_auth = 0;

#define MSG_NOT_AUTHZ "NOT_AUTHORIZED\r\n"
#define MSG_AUTH_GRANTED "AUTH_GRANTED\r\n"
#define MSG_AUTH_FAILED "AUTH_FAILED\r\n"

#define MSG_AUTH_USER_FOUND "NONCE %s\r\n"
#define MSG_AUTH_USER_NOT_FOUND "AUTH_USER_NOT_FOUND\r\n"

#define AUTH1_MAX_LENGTH (LINE_BUF_SIZE - CMD_AUTH1_LEN)
#define AUTH2_MAX_LENGTH (LINE_BUF_SIZE - CMD_AUTH2_LEN)

void
SET_AUTH()
{
    use_auth = 1;
}

int
IS_AUTH()
{
    return use_auth == 1;
}
/* temp start */
void
printRecord(struct AUTH_RECORD_LIST* record)
{
    printf("AR: %s %s\n", record->user, record->hash);
}

void
printStorage()
{
    struct AUTH_RECORD_LIST *record = authStorage;
    while (record != NULL) {
        printRecord(record);
        record = record->next;
    }
}
/* temp end */
/****** crypt/hash util *****/
void*
zalloc(int n)
{
    void *p;

    p = malloc(n);
    if (p) {
        memset(p, 0, n);
    }
    return p;
}

void
bytes2String(
    char* out,
    unsigned char* in,
    int in_size)
{
    memset(out, 0, (in_size * 2) + 1);

    int i;
    for (i = 0; i < in_size; i++) {
        sprintf(out + (2 * i), "%.2X", in[i]);
    }
}

inline int
COUNT_CHARS(char* s, char c)
{
    return *s == '\0' ? 0 : COUNT_CHARS(s + 1, c) + (*s == c);
}
void
toUpper(char* in)
{
    int i, n = strlen(in);
    for (i = 0; i < n; i++) {
        in[i] = toupper(in[i]);
    }
}
char *
trim(char *str)
{
    char *end;
    while (isspace(*str))
        str++;

    if (*str == '\0')  // All spaces?
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    *(end + 1) = '\0';

    return str;
}
char**
split(char* str, char* sep, size_t* len)
{
    if (str == NULL || str[0] == '\0') {
        *len = 0;
        return NULL;
    }
    int i, sc;
    sc = COUNT_CHARS(str, sep[0]) + 1;

    char** ret = (char**) malloc(sizeof(char*) * sc);
    *len = 0;
    char *rest = strdup(str);
    char *token;
    i = 0;
    while (i < sc) {
        token = strsep(&rest, sep);
        ret[i] = malloc(strlen(token) + 1);
        ret[i] = token;
        i++;
    }
    *len = sc;
    return ret;
}

struct AUTH_RECORD_LIST*
createRecord(char *user, char *hash)
{
    struct AUTH_RECORD_LIST *record = malloc(sizeof(struct AUTH_RECORD_LIST));
    if (record) {
        record->user = strdup(user);
        record->hash = strdup(hash);
        toUpper(record->hash);
        record->next = NULL;
        return record;
    }
    return NULL;
}

int
addRecord(char *user, char *hash)
{
    struct AUTH_RECORD_LIST *record = createRecord(user, hash);
    if (!record) {
        return 0;
    }
    if (NULL == authStorage) {
        authStorage = record;
    } else {
        struct AUTH_RECORD_LIST *last = authStorage;
        while (last->next != NULL) {
            last = last->next;
        }
        last->next = record;
    }
    return 1;

}

struct AUTH_RECORD_LIST*
searchRecord(char* auth1)
{
    struct AUTH_RECORD_LIST *record = authStorage;
    while (record != NULL) {
        if (strcmp(record->user, auth1) == 0) {
            return record;
        } else {
            record = record->next;
        }
    }
    return NULL;
}

int
loadAuthStorage(char* path)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(path, "r");
    if (fp == NULL) return -1;

    while ((read = getline(&line, &len, fp)) != -1) {
        line = trim(line);
        if (line[0] != '#') {
            size_t slen = 0;
            char** words = split(line, ":", &slen);
            if (slen == 2) {
                addRecord(words[0], words[1]);
            }
        }
    }
    fclose(fp);
#ifdef DEBUG
    printStorage();
#endif
    return authStorage != NULL ? 1 : 0;
}

void
generateNonce(char* out, int length)
{
    int bin_length = length / 2;
    unsigned char buf[bin_length];

    FILE * fd = fopen("/dev/urandom", "r");
    if (fd != NULL) {
        int rc = fread(buf, bin_length, 1, fd);
        if (!rc) rc = fread(buf, bin_length, 1, fd); // give it another chance
        /*WORST-CASE-SCENARIO ... fails to read -> nonce is all 0 if nothing blows up :D */
        fclose(fd);
    }

    return bytes2String(out, buf, bin_length);
}

void
doMd5(char* out, char* in)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, in, strlen(in));
    unsigned char res[16];
    MD5_Final(res, &ctx);

    return bytes2String(out, res, 16);
}

void
do_auth1(conn conn, char* auth1)
{
    struct AUTH_RECORD_LIST *record = searchRecord(auth1);
    if (NULL == record) {
        reply_msg(conn, MSG_AUTH_USER_NOT_FOUND);
        return;
    }

    conn->auth->record = record;
    if (strlen(conn->auth->nonce) == 0) {
        generateNonce(conn->auth->nonce, NONCE_SIZE);
        reply_line(conn, STATE_SENDWORD, MSG_AUTH_USER_FOUND, conn->auth->nonce);
    }
}

void
do_auth2(conn conn, char* auth2)
{
    if (conn->auth->auth_ok) {
        return;
    }

    int n = strlen(conn->auth->record->hash) + 18;
    // 16 = strlen((char*)conn->auth->nonce), 1 for ":", 1 for \0
    char *tmp = zalloc(n);
    sprintf(tmp, "%s:%s", conn->auth->record->hash, conn->auth->nonce);

    char hash[33];
    doMd5(hash, tmp);

    conn->auth->auth_ok = (strcmp(hash, auth2) == 0);
    free(tmp);

    if (conn->auth->auth_ok) {
        reply_msg(conn, MSG_AUTH_GRANTED);
    }
    else {
        reply_msg(conn, MSG_AUTH_FAILED);
    }
}

void
authConn(conn conn, int op)
{
    if (!(IS_AUTH() && op != OP_UNKNOWN && op != OP_QUIT)) {
        return;
    }

    if (!conn->auth) {
        reply_serr(conn, MSG_INTERNAL_ERROR);
        return;
    }

    if (conn->auth->auth_ok) {
        return;
    }

    char* name=NULL;
    size_t len=0;

    switch (op) {
        case OP_AUTH1:
            name = conn->cmd + CMD_AUTH1_LEN;
            len = strlen(name);
            if ((len <= 0) || (len > AUTH1_MAX_LENGTH)) {
                reply_msg(conn, MSG_BAD_FORMAT);
                return;
            }
            do_auth1(conn, name);
            break;

        case OP_AUTH2:
            name = conn->cmd + CMD_AUTH2_LEN;
            len = strlen(name);
            if ((len <= 0) || (len > AUTH1_MAX_LENGTH) || (len % 16)) {
                reply_msg(conn, MSG_BAD_FORMAT);
                return;
            }
            do_auth2(conn, name);
            break;
    }

    if (conn->state != STATE_SENDWORD && !conn->auth->auth_ok) {
        reply_msg(conn, MSG_NOT_AUTHZ);
        return;
    }
}
