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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
/* creds repo */
struct AUTH_RECORD_LIST *authStorage = NULL;
static int use_auth = 0;

#define MSG_NOT_AUTHZ "NOT_AUTHORIZED\r\n"
#define MSG_AUTH_GRANTED "AUTH_GRANTED\r\n"
#define MSG_AUTH_FAILED "AUTH_FAILED\r\n"

#define MSG_AUTH_USER_FOUND "NONCE %s\r\n"
#define MSG_AUTH_USER_NOT_FOUND "AUTH_USER_NOT_FOUND\r\n"


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
split(char* input, const char* delim, size_t* out_len)
{
    char** out = NULL;
    int size = 0;

    char* saveptr;
    char* word;

    word = strtok_r(input, delim, &saveptr);
    while (word != NULL) {
        out = realloc(out, sizeof(char*) * (size + 1));
        out[size++] = strdup(word);
        word = strtok_r(NULL, delim, &saveptr);
    }
    *out_len = size;
    return out;
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
        char* trimed_line = trim(line);
        if (trimed_line[0] != '#') {
            size_t slen = 0;
            char** words = split(trimed_line, ":", &slen);
            if (slen == 2) {
                addRecord(words[0], words[1]);
            }

            /* Cleanup the mallocs form split. */
            int i;
            for (i=0; i < slen; ++i) {
                free(words[i]);
            }
            free(words);
        }
    }
    free(line);
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

    FILE* fd = fopen("/dev/urandom", "r");
    if (fd != NULL) {
        int rc = fread(buf, 1, bin_length, fd);
        fclose(fd);

        /* If the fread fails, use at least pseudo randomness. */
        if (rc != bin_length) {
            int i;
            for (i=0; i < bin_length; ++i) {
                buf[i] = (unsigned char)(random());
            }
        }
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

    /* +2 for ':' and null byte. */
    int sig_len = strlen(conn->auth->record->hash) + NONCE_SIZE + 2;
    char signature[sig_len];
    sprintf(signature, "%s:%s", conn->auth->record->hash, conn->auth->nonce);

    char hash[33];
    doMd5(hash, signature);

    conn->auth->auth_ok = (strcmp(hash, auth2) == 0);

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
            if (len <= 0) {
                reply_msg(conn, MSG_BAD_FORMAT);
                return;
            }
            do_auth1(conn, name);
            break;

        case OP_AUTH2:
            name = conn->cmd + CMD_AUTH2_LEN;
            len = strlen(name);
            if ((len <= 0) || (len % 16)) {
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
