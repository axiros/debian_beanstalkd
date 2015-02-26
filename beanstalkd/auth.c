/*
 * auth.c
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#include "auth.h"
#include "prot.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "md5.h"

/* creds repo */
struct AUTH_RECORD_LIST *authStorage = NULL;
static int use_auth = 0;

#define MSG_NOT_AUTHZ "NOT_AUTHORIZED\r\n"
#define MSG_AUTH_GRANTED "AUTH_GRANTED\r\n"

#define MSG_AUTH_USER_FOUND "NONCE %s\r\n"
#define MSG_AUTH_USER_NOT_FOUND "AUTH_USER_NOT_FOUND\r\n"

#define AUTH1_MAX_LENGTH LINE_BUF_SIZE - CMD_AUTH1_LEN
#define AUTH2_MAX_LENGTH LINE_BUF_SIZE - CMD_AUTH2_LEN

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
    printf("AR: %s %d %s\n", record->user, (int) record->level, record->hash);
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
uint8_t*
string2Bytes(char *in)
{
    int i, n = strlen(in) / 2;
    uint8_t *out = zalloc(n + 1);
    char tmp[3];

    for (i = 0; i < n; i++) {
        tmp[0] = in[2 * i];
        tmp[1] = in[2 * i + 1];
        tmp[2] = '\0';
        out[i] = (uint8_t) strtol(tmp, NULL, 16);
    }
    return out;
}

char*
bytes2String(uint8_t * in, int n)
{
    char *out = zalloc(2 * n + 1);
    int i;
    for (i = 0; i < n; i++) {
        sprintf(out + (2 * i), "%.2X", in[i]);
    }
    return out;
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

static ACCES_LEVEL
getLevelFromString(const char* levelString)
{
#define TEST_LVLS(s,c,o) if (strncmp((s), (c), CONSTSTRLEN(c)) == 0) return (o);
    TEST_LVLS(levelString, GROUP_ADMIN, ALL);
    TEST_LVLS(levelString, GROUP_PRODUCER, PRODUCER);
    TEST_LVLS(levelString, GROUP_CONSUMER, CONSUMER);
    TEST_LVLS(levelString, GROUP_MONITOR, MONITOR);
    return DENIED;
}
static char*
getStringFromLevel(ACCES_LEVEL level)
{
#define TEST_LVLL(s,c,o) if (s==c) return (o);
    TEST_LVLL(level, ALL, GROUP_ADMIN);
    TEST_LVLL(level, PRODUCER, GROUP_PRODUCER);
    TEST_LVLL(level, CONSUMER, GROUP_CONSUMER);
    TEST_LVLL(level, MONITOR, GROUP_MONITOR);
    return "";
}

struct AUTH_RECORD_LIST*
createRecord(char *user, ACCES_LEVEL level, char *hash)
{
    struct AUTH_RECORD_LIST *record = malloc(sizeof(struct AUTH_RECORD_LIST));
    if (record) {
        record->user = strdup(user);
        record->level = level;
        record->hash = strdup(hash);
        toUpper(record->hash);
        record->next = NULL;
        return record;
    }
    return NULL;
}

int
addRecord(char *user, ACCES_LEVEL level, char *hash)
{
    struct AUTH_RECORD_LIST *record = createRecord(user, level, hash);
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
            if (slen == 3) {
                ACCES_LEVEL level = getLevelFromString(words[1]);
                if (DENIED != level) {
                    addRecord(words[0], level, words[2]);
                }
            }
        }
    }
    fclose(fp);
#ifdef DEBUG
    printStorage();
#endif
    return authStorage != NULL ? 1 : 0;
}

uint8_t*
generateNonce(int length)
{
    uint8_t* buf = zalloc(length);
    FILE * fd = fopen("/dev/urandom", "r");
    if (fd != NULL) {
        int rc = fread(buf, length, 1, fd);
        if (!rc) rc = fread(buf, length, 1, fd); // give it another chance
        /*WORST-CASE-SCENARIO ... fails to read -> nonce is all 0 if nothing blows up :D */
        fclose(fd);
    }
    return buf;
}
char*
decodeAES(uint8_t* iv, char* in)
{
    int n = strlen(in) / 2;
    char *out = zalloc(n + 1);
    uint8_t *data = string2Bytes(in);
    AES128_CBC_decrypt_buffer((uint8_t*) out, data, n, AES_KEY, iv);
    // XXX:
    free(data);
    return out;
}

char*
doMd5(char* in)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, in, strlen(in));
    uint8_t res[16];
    MD5_Final(res, &ctx);
    return bytes2String(res, 16);
}

char*
computePasswdHash(char* user, ACCES_LEVEL level, char* passwd)
{
    char* lvl = getStringFromLevel(level);
    int sL = strlen(user) + strlen(lvl) + strlen(passwd) + 2 + 1;
    char *tmp = zalloc(sL);
    sprintf(tmp, "%s:%s:%s", user, lvl, passwd);
    char *out = doMd5(tmp);
    free(tmp);
    return out;
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
    if (strlen((char*) conn->auth->nonce) == 0) {
        uint8_t *nonce = generateNonce(16);
        free(conn->auth->nonce);
        conn->auth->nonce = nonce;
        char *sNonce = bytes2String(conn->auth->nonce, 16);
        reply_line(conn, STATE_SENDWORD, MSG_AUTH_USER_FOUND, sNonce);
        return;
    }
}

void
do_auth2(conn conn, char* auth2)
{
    if (conn->auth->auth_ok) return;
    char *passwd = decodeAES(conn->auth->nonce, auth2);
    dbgprintf(">passwd %s\n", passwd);
    char *hash = computePasswdHash(conn->auth->record->user,
                                   conn->auth->record->level, passwd);
    dbgprintf(">hash %s %s\n", hash, conn->auth->record->hash);

    conn->auth->auth_ok = (strcmp(hash, conn->auth->record->hash) == 0);
    free(passwd);
    free(hash);
    reply_msg(conn, MSG_AUTH_GRANTED);
}

void
authConn(conn conn, int op)
{
    if (IS_AUTH() && op != OP_UNKNOWN && op != OP_QUIT) {
        if (!conn->auth) {
            reply_serr(conn, MSG_INTERNAL_ERROR);
            return;
        }
        if (conn->auth->auth_ok) return;
        char* name;
        size_t len;
        switch (op) {
            case OP_AUTH1:
                name = conn->cmd + CMD_AUTH1_LEN;
                len = strlen(name);
                if (len <= 0 || len > AUTH1_MAX_LENGTH) {
                    reply_msg(conn, MSG_BAD_FORMAT);
                    return;
                }
                do_auth1(conn, name);
                break;
            case OP_AUTH2:
                name = conn->cmd + CMD_AUTH2_LEN;
                len = strlen(name);
                if (len <= 0 || len > AUTH1_MAX_LENGTH || len % 16) {
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
}

