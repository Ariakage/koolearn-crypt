/*
 * oracle.c - 通过 dlopen 加载 koolearn-decrypt 的 decrypt.node，
 *           直接调用其内部 C 密码原语，作为 Go 复刻的"真值 oracle"。
 *
 * 原理：decrypt.node 是 -undefined dynamic_lookup 的 Node native addon，
 *       底层 C 函数全部导出且符号未 strip。只要不触碰 V8 层（libdecrypt.cc），
 *       dlopen(RTLD_LAZY) 即可加载，dlsym 可取到所有 C 符号。
 *
 * 构建：bash harness/build.sh
 * 用法：./harness/oracle [path/to/decrypt.node]  < commands.txt
 *
 * stdin 协议（每行一条命令，空白分隔，# 开头为注释）：
 *   caesar      <hex_src> <hex_key>             -> hex_dst   (Caesar_Decrypt)
 *   caesar_enc  <hex_src> <hex_key>             -> hex_dst   (Caesar_Encrypt)
 *   fence       <hex_src> <hex_key>             -> hex_dst   (Fence_Decrypt)
 *   fence_enc   <hex_src> <hex_key>             -> hex_dst   (Fence_Encrypt)
 *   rc4         <hex_src> <hex_key>             -> hex_src'  (原地)
 *   md5         <hex_src>                       -> hex16
 *   decryptplan <hex_plans> <hex_key> <hex_data>-> "<len> <hex>"
 *   test        <hex_data>                      -> int
 *   test2       <hex_data>                      -> int
 *   aessetkey   <hex_key>                       -> ok         (探测签名)
 *   aesecbdec   <hex_data> <hex_key>            -> hex_dst   (AesDecryptECB)
 *   aesecbenc   <hex_data> <hex_key>            -> hex_dst   (AesEncryptECB)
 *   sha1        <hex_data>                      -> hex20      (SHA1 摘要)
 *   hashtag     <hex_data>                      -> "<ret> <tagType> <hash16>" (createHashTag)
 *   createkey   <hex_eKey> <klen> <hex_basekey> <blen> <expires> <hex_token> <useKey> -> hex16
 *   decryptparse <hex_container> <hex_ctxkey> <useKey> <expires> <hex_token> -> "<ret> <len> <hex>"
 *   encryptparse <hex_plain> <hex_ctxkey> <useKey> <useToken> <hex_token> <expires> -> "<len> <hex_container>"
 *   quit                                        -> 退出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

typedef unsigned char uchar;

/* ---- struct.h 还原布局（已用 DWARF + 反汇编交叉确认） ---- */
typedef struct {                 /* 40B (0x28) */
    int      length;             /* +0x00 */
    uint16_t tagType;            /* +0x04 */
    char     EncryptType;        /* +0x06 */
    short    PlansLength;        /* +0x08 */
    char    *Plans;              /* +0x10 */
    short    KeyLength;          /* +0x18 */
    char    *Key;                /* +0x20 */
} encryptTag;

typedef struct {                 /* 16B (0x10) */
    uint16_t tagType;            /* +0x00 */
    int      length;             /* +0x04 */
    char    *data;               /* +0x08 */
} dataTag;

typedef struct {                 /* 512B */
    unsigned char space[512];
} AesCtx;

typedef struct {                 /* 72B (0x48) */
    int       length;            /* +0x00 */
    uint8_t  *data;              /* +0x08 */
    int       useKey;            /* +0x10 */
    uint8_t   key[16];           /* +0x14 */
    int64_t   expires;           /* +0x28 */
    int       useToken;          /* +0x30 */
    uint8_t  *token;             /* +0x38 */
    size_t    tokenLen;          /* +0x40 */
} Pasrser_CTX;

/* ---- 运行时符号解析 ---- */
static void *H;

static void *S(const char *name)
{
    void *p = dlsym(H, name);
    if (!p) {
        fprintf(stderr, "dlsym failed: %s (%s)\n", name, dlerror());
        exit(2);
    }
    return p;
}

/* ---- hex 编解码 ---- */
static int hv(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(const char *s, uint8_t *out, size_t maxout)
{
    size_t n = 0;
    while (*s) {
        int a = hv(*s++);
        int b = hv(*s++);
        if (a < 0 || b < 0) return -1;
        if (n >= maxout) return -1;
        out[n++] = (uint8_t)((a << 4) | b);
    }
    return (int)n;
}

static void print_hex(const uint8_t *p, int n)
{
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

#define MAXBUF (1 << 20)

int main(int argc, char **argv)
{
    /* stdout 可能是管道（被 Go 测试驱动），必须关闭全缓冲，否则应答会
     * 滞留在 stdio 缓冲区里，调用方永远读不到，直接死锁。 */
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *lib = argc > 1 ? argv[1]
                               : "reference/koolearn-decrypt/decrypt.node";
    H = dlopen(lib, RTLD_LAZY | RTLD_LOCAL);
    if (!H) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "oracle: loaded %s\n", lib);

    static char    line[2 * MAXBUF];
    static uint8_t src[MAXBUF], key[8192], plans[8192], out[MAXBUF];

    while (fgets(line, sizeof line, stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;

        char *cmd = strtok(p, " \t");
        if (!cmd) continue;

        if (!strcmp(cmd, "quit")) break;

        if (!strcmp(cmd, "caesar") || !strcmp(cmd, "fence") ||
            !strcmp(cmd, "caesar_enc") || !strcmp(cmd, "fence_enc")) {
            char *a = strtok(NULL, " \t"), *b = strtok(NULL, " \t");
            if (!a || !b) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            int k = hex2bin(b, key, sizeof key);
            if (n < 0 || k < 0) { printf("ERR hex\n"); continue; }
            const char *sym = "Caesar_Decrypt";
            if (!strcmp(cmd, "fence"))           sym = "Fence_Decrypt";
            else if (!strcmp(cmd, "caesar_enc")) sym = "Caesar_Encrypt";
            else if (!strcmp(cmd, "fence_enc"))  sym = "Fence_Encrypt";
            void (*fn)(const uchar *, int, uchar *, int, uchar *) =
                (void (*)(const uchar *, int, uchar *, int, uchar *))S(sym);
            memcpy(out, src, n);
            fn(src, n, key, k, out);
            print_hex(out, n);
            continue;
        }

        if (!strcmp(cmd, "rc4")) {
            char *a = strtok(NULL, " \t"), *b = strtok(NULL, " \t");
            if (!a || !b) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            int k = hex2bin(b, key, sizeof key);
            if (n < 0 || k < 0) { printf("ERR hex\n"); continue; }
            void (*fn)(char *, int, char *, int) =
                (void (*)(char *, int, char *, int))S("my_RC4");
            memcpy(out, src, n);
            fn((char *)out, n, (char *)key, k);
            print_hex(out, n);
            continue;
        }

        if (!strcmp(cmd, "md5")) {
            char *a = strtok(NULL, " \t");
            if (!a) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            if (n < 0) { printf("ERR hex\n"); continue; }
            void (*fn)(uint8_t *, size_t, uint8_t *) =
                (void (*)(uint8_t *, size_t, uint8_t *))S("GetMd5");
            fn(src, (size_t)n, out);
            print_hex(out, 16);
            continue;
        }

        if (!strcmp(cmd, "decryptplan")) {
            char *pa = strtok(NULL, " \t"), *ka = strtok(NULL, " \t"),
                 *da = strtok(NULL, " \t");
            if (!pa || !ka || !da) { printf("ERR args\n"); continue; }
            int np = hex2bin(pa, plans, sizeof plans);
            int nk = hex2bin(ka, key, sizeof key);
            int nd = hex2bin(da, src, sizeof src);
            if (np < 0 || nk < 0 || nd < 0) { printf("ERR hex\n"); continue; }

            encryptTag et;
            memset(&et, 0, sizeof et);
            et.EncryptType = 1;
            et.PlansLength = (short)np;
            et.Plans       = (char *)plans;
            et.KeyLength   = (short)nk;
            et.Key         = (char *)key;

            dataTag dt;
            memset(&dt, 0, sizeof dt);
            memcpy(out, src, nd);

            void (*fn)(dataTag *, encryptTag *, char *, char *, int) =
                (void (*)(dataTag *, encryptTag *, char *, char *, int))S(
                    "decryptByPlan");
            fn(&dt, &et, (char *)key, (char *)out, nd);

            printf("%d ", dt.length);
            print_hex((uint8_t *)dt.data, dt.length);
            free(dt.data); /* decryptByPlan 内部 malloc，归还避免泄漏 */
            continue;
        }

        if (!strcmp(cmd, "test") || !strcmp(cmd, "test2")) {
            char *a = strtok(NULL, " \t");
            if (!a) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            if (n < 0) { printf("ERR hex\n"); continue; }
            int (*fn)(int, uchar *) =
                (int (*)(int, uchar *))S(!strcmp(cmd, "test") ? "test"
                                                               : "test_version2");
            printf("%d\n", fn(n, src));
            continue;
        }

        if (!strcmp(cmd, "aesecbdec") || !strcmp(cmd, "aesecbenc")) {
            char *da = strtok(NULL, " \t"), *ka = strtok(NULL, " \t");
            if (!da || !ka) { printf("ERR args\n"); continue; }
            int nd = hex2bin(da, src, sizeof src);
            int nk = hex2bin(ka, key, sizeof key);
            if (nd < 0 || nk < 0) { printf("ERR hex\n"); continue; }
            AesCtx ctx;
            memset(&ctx, 0, sizeof ctx);
            void (*setkey)(AesCtx *, int, int, uchar *, int) =
                (void (*)(AesCtx *, int, int, uchar *, int))S("AesSetKey");
            void (*dec)(AesCtx *, uchar *, uchar *, int) =
                (void (*)(AesCtx *, uchar *, uchar *, int))S(
                    !strcmp(cmd, "aesecbdec") ? "AesDecryptECB" : "AesEncryptECB");
            setkey(&ctx, 0, 0, key, 0);
            memcpy(out, src, nd);
            dec(&ctx, out, out, nd);
            print_hex(out, nd);
            continue;
        }

        if (!strcmp(cmd, "sha1")) {
            char *a = strtok(NULL, " \t");
            if (!a) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            if (n < 0) { printf("ERR hex\n"); continue; }
            uint8_t ctx[0x68];
            memset(ctx, 0, sizeof ctx);
            void (*reset)(void *) = (void (*)(void *))S("SHA1Reset");
            void (*input)(void *, const uint8_t *, unsigned) =
                (void (*)(void *, const uint8_t *, unsigned))S("SHA1Input");
            int  (*result)(void *) = (int (*)(void *))S("SHA1Result");
            reset(ctx);
            input(ctx, src, (unsigned)n);
            if (!result(ctx)) { printf("ERR sha1\n"); continue; }
            print_hex(ctx, 20);
            continue;
        }

        if (!strcmp(cmd, "hashtag")) {
            char *a = strtok(NULL, " \t");
            if (!a) { printf("ERR args\n"); continue; }
            int n = hex2bin(a, src, sizeof src);
            if (n < 0) { printf("ERR hex\n"); continue; }
            struct { uint16_t tagType; uint8_t hash[16]; } tag;
            memset(&tag, 0, sizeof tag);
            int (*fn)(void *, uint8_t *, size_t) =
                (int (*)(void *, uint8_t *, size_t))S("createHashTag");
            int r = fn(&tag, src, (size_t)n);
            printf("%d %04x ", r, tag.tagType);
            print_hex(tag.hash, 16);
            continue;
        }

        if (!strcmp(cmd, "createkey")) {
            char *ka = strtok(NULL, " \t"), *kla = strtok(NULL, " \t"),
                 *ba = strtok(NULL, " \t"), *bla = strtok(NULL, " \t"),
                 *ea = strtok(NULL, " \t"), *ta = strtok(NULL, " \t"),
                 *ua = strtok(NULL, " \t");
            if (!ka || !kla || !ba || !bla || !ea || !ta || !ua) {
                printf("ERR args\n"); continue;
            }
            int nk = hex2bin(ka, src, sizeof src);
            int nb = hex2bin(ba, key, sizeof key);
            int nt = hex2bin(ta, plans, sizeof plans);
            if (nk < 0 || nb < 0 || nt < 0) { printf("ERR hex\n"); continue; }
            encryptTag et;
            memset(&et, 0, sizeof et);
            et.KeyLength = (short)atoi(kla);
            et.Key       = (char *)src;
            int (*fn)(encryptTag *, uint8_t *, uint32_t, int64_t, uint8_t *, int, uint8_t *) =
                (int (*)(encryptTag *, uint8_t *, uint32_t, int64_t, uint8_t *, int, uint8_t *))S("createKey");
            fn(&et, key, (uint32_t)atoi(bla), (int64_t)atoll(ea), plans, atoi(ua), out);
            print_hex(out, 16);
            continue;
        }

        if (!strcmp(cmd, "decryptparse")) {
            char *ca = strtok(NULL, " \t"), *ka = strtok(NULL, " \t"),
                 *ua = strtok(NULL, " \t"), *ea = strtok(NULL, " \t"),
                 *ta = strtok(NULL, " \t");
            if (!ca || !ka || !ua || !ea || !ta) { printf("ERR args\n"); continue; }
            int nc = hex2bin(ca, src, sizeof src);
            int nk = hex2bin(ka, key, sizeof key);
            int nt = hex2bin(ta, plans, sizeof plans);
            if (nc < 0 || nk < 0 || nt < 0) { printf("ERR hex\n"); continue; }
            Pasrser_CTX ctx;
            memset(&ctx, 0, sizeof ctx);
            ctx.useKey   = atoi(ua);
            memcpy(ctx.key, key, nk > 16 ? 16 : nk);
            ctx.expires  = (int64_t)atoll(ea);
            ctx.token    = plans;
            ctx.tokenLen = (size_t)nt;
            int (*fn)(Pasrser_CTX *, uint8_t *, int) =
                (int (*)(Pasrser_CTX *, uint8_t *, int))S("decrypt_parse");
            int r = fn(&ctx, src, nc);
            printf("%d %d ", r, ctx.length);
            if (ctx.length > 0 && ctx.length <= MAXBUF) print_hex(ctx.data, ctx.length);
            else printf("\n");
            continue;
        }

        if (!strcmp(cmd, "encryptparse")) {
            char *pa = strtok(NULL, " \t"), *ka = strtok(NULL, " \t"),
                 *ua = strtok(NULL, " \t"), *ut = strtok(NULL, " \t"),
                 *tta = strtok(NULL, " \t"), *ea = strtok(NULL, " \t");
            if (!pa || !ka || !ua || !ut || !tta || !ea) { printf("ERR args\n"); continue; }
            int np = hex2bin(pa, src, sizeof src);
            int nk = hex2bin(ka, key, sizeof key);
            int nt = hex2bin(tta, plans, sizeof plans);
            if (np < 0 || nk < 0 || nt < 0) { printf("ERR hex\n"); continue; }
            Pasrser_CTX ctx;
            memset(&ctx, 0, sizeof ctx);
            ctx.useKey   = atoi(ua);
            memcpy(ctx.key, key, nk > 16 ? 16 : nk);
            ctx.expires  = (int64_t)atoll(ea);
            ctx.useToken = atoi(ut);
            ctx.token    = plans;
            ctx.tokenLen = (size_t)nt;
            void (*fn)(Pasrser_CTX *, uint8_t *, int) =
                (void (*)(Pasrser_CTX *, uint8_t *, int))S("encrypt_parse");
            fn(&ctx, src, np);
            printf("%d ", ctx.length);
            print_hex(ctx.data, ctx.length);
            free(ctx.data);
            continue;
        }

        printf("ERR unknown cmd: %s\n", cmd);
    }

    dlclose(H);
    return 0;
}
