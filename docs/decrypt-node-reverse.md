# koolearn-decrypt 逆向工作笔记（真值来源）

来源二进制: `reference/koolearn-decrypt/decrypt.node` (Mach-O x86_64 bundle, 124696 B, md5 `cd17c57abae891565f0d5d9e4c765e7c`)
dSYM: `decrypt.node.dSYM` (DWARF 393KB, Apple clang 14, Jenkins CI: neibu-wm-daxue-koolearn)
构建路径: `/Users/Shared/work/yd-jenkins/workspace/neibu-wm-daxue-koolearn/app/node_modules/koolearn-decrypt/build/`

## 源文件构成 (14)
`aes.c AESDecode.c AESEncode.c EfAes.h` | `caesar.c rc4.c fence.c` | `md5.c sha1.c` |
`header.c tag.c parser.c struct.h` | `encrypt.c common.c` | `libdecrypt.cc` (NAN 绑定)

## 验证条件
- clang -arch x86_64 可用, Rosetta 可用 → 能编译运行 x86_64 harness
- decrypt.node 是 native 模块(dynamic_lookup), `dlopen(RTLD_LAZY)` 成功,
  底层 C 密码函数全部 dlsym 可调用(不碰 V8 层即可)。已验证可调用:
  `decryptByPlan/decrypt_parse/createKey/getData/getExpires/Caesar_Decrypt/my_RC4/`
  `Fence_Decrypt/GetMd5/createHeader/encryptByPlan/test/test_version2/padding/KeyExpansion`

## 数据结构 (struct.h)
```c
typedef struct {              // header, struct.h:8, 6 bytes
    char     flag[4];         // +0x00  = "KEY."  (LE 字节: 4b 45 59 2e)
    uint16_t vesion;          // +0x04  = 2   [源码拼写就是 vesion]
} header;

typedef struct {              // encryptTag, struct.h:15, 40 bytes (0x28)
    int      length;          // +0x00
    uint16_t tagType;         // +0x04
    char     EncryptType;     // +0x06   (==1 才会解密)
    short    PlansLength;     // +0x08
    char*    Plans;           // +0x10   (每轮一个 plan 字节)
    short    KeyLength;       // +0x18
    char*    Key;             // +0x20
} encryptTag;

typedef struct {              // dataTag, struct.h:35, 16 bytes (0x10)
    uint16_t tagType;         // +0x00
    int      length;          // +0x04
    char*    data;            // +0x08
} dataTag;

typedef struct {              // tokenTag, struct.h:46, 18 bytes (0x12)
    uint16_t tagType;         // +0x00
    uint8_t  token[16];       // +0x02   (token 的 MD5)
} tokenTag;

typedef struct {              // expiresTag, struct.h:55, 32 bytes (0x20)
    uint16_t tagType;         // +0x00
    int64_t  expires;         // +0x08
    uint8_t  expiresData[16]; // +0x10   (expires 的加密块)
} expiresTag;

typedef struct {              // hashTag, struct.h:66, 18 bytes (0x12)
    uint16_t tagType;         // +0x00
    uint8_t  hash[16];        // +0x02   (数据的 MD5)
} hashTag;

typedef struct {              // Pasrser_CTX, parser.h:22, 72 bytes (0x48)
    int      length;          // +0x00
    uint8_t* data;            // +0x08
    int      useKey;          // +0x10
    uint8_t  key[16];         // +0x14
    int64_t  expires;         // +0x28
    int      useToken;        // +0x30
    uint8_t* token;           // +0x38
    size_t   tokenLen;        // +0x40
} Pasrser_CTX;

typedef struct _AesCtx_ {     // AesCtx, EfAes.h:16, 512 bytes
    unsigned char space[512]; // +0x00  (AES 轮密钥调度存储)
} AesCtx;
```

## 函数签名 (调用点反汇编为准, DWARF 参数名顺序可能被打乱)
```c
// encrypt.c
void encryptByPlan(dataTag* tag, encryptTag* e_tag, char* key, const uint8_t* p_data, int size); // L12, 0x6f80
void decryptByPlan(dataTag* tag, encryptTag* e_tag, char* key, char* p_data, int size);           // L75, 0x7140
void GetMd5(uint8_t* p_src, size_t size, uint8_t* p_dst);   // L176, 0x7390 (MD5, 16B 输出)
void createPartKey(char* key, int p_size);                  // L184, 0x7400 (rand 填充)

// caesar.c — 调用: Caesar_Decrypt(buf, size, key, 16, buf) 原地
void Caesar_Encrypt(const uchar* src, int slen, uchar* key, int klen, uchar* dst); // L3
void Caesar_Decrypt(const uchar* src, int slen, uchar* key, int klen, uchar* dst); // L12, 0x6f00

// fence.c — 调用: Fence_Decrypt(buf, size, key, 16, buf) 原地
void Fence_Encrypt(const uchar* src, int slen, uchar* key, int klen, uchar* dst); // L20
void Fence_Decrypt(const uchar* src, int slen, uchar* key, int klen, uchar* dst); // L44, 0xe5e0

// rc4.c — 调用: my_RC4(buf, size, key, 16) 原地
void my_RC4(char* src, int slen, char* key, int keylen); // L47, 0xd640

// header.c
void createHeader(header* p_header); // L5, 0x7440 (写 flag="KEY.", vesion=2)

// tag.c
int createEncryptTag(encryptTag* p_tag); // L3
int createDataTag(dataTag* tag, encryptTag* e_tag, uint8_t* data, uint32_t size, uint8_t* key); // L33
int createExpiresTag(expiresTag* tag, encryptTag* e_tag, uint8_t* key); // L40
int createTokenTag(tokenTag* tag, uint8_t* token, int32_t len); // L53
int createHashTag(hashTag* tag, uint8_t* data, size_t len); // L60
int createKey(encryptTag* e_tag, uint8_t* basekey, uint32_t keylen, int64_t expires, uint8_t* token, int useKey, uint8_t* out); // L104, 0xdc50
int encryptTagWriteInto(uint8_t** dst, encryptTag tag); // L140
int dataTagWriteInto(uint8_t** dst, dataTag tag);       // L153
int expiresTagWriteInto(uint8_t** dst, expiresTag tag); // L163
int tokenTagWriteInto(uint8_t** dst, tokenTag tag);     // L173
int hashTagWriteInto(uint8_t** dst, hashTag tag);       // L183
int headWriteInto(uint8_t** dst, header head);          // L191
int encryptTagRead(uint8_t* src, encryptTag* tag);      // L197
int dataTagRead(uint8_t* src, dataTag* tag);            // L216
int expiresTagRead(uint8_t* src, expiresTag* tag);      // L227
int tokenTagRead(uint8_t* src, tokenTag* tag);          // L238
int hashTagRead(uint8_t* src, hashTag* tag);            // L249
int64_t getExpires(expiresTag e, encryptTag et, uint8_t* key); // L259, 0xe0f0
int getData(encryptTag et, uint8_t* key, uint8_t* src, size_t size, dataTag* out); // L277

// parser.c
void encrypt_parse(Pasrser_CTX* ctx, uint8_t* data, int len); // L52, 0x22b0
int  decrypt_parse(Pasrser_CTX* ctx, unsigned char* data, int len); // L123, 0x2540
unsigned int test(int len, unsigned char* data);   // L251, 0x2930 (往返自测)
int test_version2(int len, unsigned char* data);   // L303, 0x2aa0 (带 token 往返自测)

// libdecrypt.cc (NAN, 需要 V8, harness 不调用)
// CreateResult(int,uchar*,uint) / Method(Nan CB) / Init / node_register_module_v85
```

## decryptByPlan 算法 (0x7140-0x7379, 反汇编 100% 还原)
```c
void decryptByPlan(dataTag* tag, encryptTag* e_tag, char* key, char* p_data, int size) {
    if (e_tag->EncryptType != 1) { /* 不解密, 直接返回 */ }
    uchar* buf = malloc(size); memset(buf,0,size); memcpy(buf, p_data, size);
    int n = e_tag->PlansLength;                 // short @+0x8
    for (int idx = n-1; idx >= 0; idx--) {      // 逆序!
        signed char planByte = e_tag->Plans[idx];
        signed char sel = PLANS_DIC[planByte];   // 双重查表 (planByte 作有符号索引)
        if ((unsigned)sel > 3) continue;
        switch (sel) {
          case 0: Caesar_Decrypt(buf, size, key, 16, buf); break;
          case 1: my_RC4(buf, size, key, 16); break;
          case 2: Fence_Decrypt(buf, size, key, 16, buf); break;
          case 3: { AesCtx ctx; AesSetKey(&ctx,0,0,key,0); AesDecryptECB(&ctx,buf,buf,size); } break;
        }
    }
    // PKCS#7 去填充
    uchar last = buf[size-1];
    int finalLen = size;
    if (last <= 16) {                            // unsigned <=16
        finalLen = size - last;
        if (last != 0) {
            for (int i = finalLen; i < size; i++)
                if (buf[i] != last) { finalLen = size; break; }  // 填充非法→不截断
        }
        uchar* nb = malloc(finalLen); memset(nb,0,finalLen); memcpy(nb,buf,finalLen);
        free(buf); buf = nb;
    }
    tag->data = buf;        // +0x8
    tag->length = finalLen; // +0x4
}
```

## 关键常量表
PLANS_DIC[32] @0xed30 (`__TEXT,__const`):
```
03 01 00 00 03 00 02 03 03 01 03 03 01 01 01 02
03 03 00 02 00 00 01 02 03 00 03 03 02 00 01 03
```
= [3,1,0,0,3,0,2,3,3,1,3,3,1,1,1,2,3,3,0,2,0,0,1,2,3,0,3,3,2,0,1,3]

跳转表 @0x737c (相对 base 0x737c 的 int32):
```
case0 = -295 → 0x7255 Caesar_Decrypt
case1 = -252 → 0x7280 my_RC4
case2 = -220 → 0x72a0 Fence_Decrypt
case3 = -412 → 0x71e0 AesSetKey+AesDecryptECB
```

Method 魔数: `expires` 与 `0x58D10EEF` (=1489999855, 2017-03-20 UTC) 比较作版本分支开关。
JS 层硬编码 key (isKoolearnET): `"5wqPBk89IkGBxXZy"` (16B); token=user_id; expires=timestamp。

## 密码原语还原 (oracle 真值 + 反汇编双重确认)

### Caesar_Decrypt (0x6f00) — 100% 确认
```c
// dst[i] = (src[i] - key[i % klen]) & 0xff   (mod 256 环绕)
```
反汇编依据: 0x6f39 `subb (%r9,%rdx), %bl`; `idivl %ecx` 取 i%klen; 循环展开 2 次。
真值:
```
caesar 41424344 0102...10 -> 40404040
caesar 00 01              -> ff          (环绕)
caesar ff 01              -> fe
caesar 41 41              -> 00
caesar 41 42              -> ff
caesar 4142434445 01020304     -> 4040404044      (第5字节回绕 key[0])
caesar 4142434445464748 0102   -> 4040424244444646
```

### my_RC4 (0xd640) — 100% 确认 = 标准 RC4（原地）
栈: S[256] @[rbp-0x220], K[256] @[rbp-0x120]。
- KSA 填充: `K[i] = key[i % keylen]` (0xd880 `idivl %ecx`)
- S 初始化: S[i]=i (S[0..0xf] 手工 mov; S[0x10..0xff] 从常量 0x13db0 加载)
- KSA 主循环 (0xd8c0): `j = (j + S[i] + K[i]) & 0xff; swap(S[i], S[j]);`
- PRGA (0xd930): `i=(i+1)&0xff; j=(j+S[i])&0xff; swap(S[i],S[j]); t=S[(S[i]+S[j])&0xff]; src[k]^=t;`
- 输出原地异或到 rdi(src)
真值: `rc4 41424344 0102...10 -> db858fde`

### Fence_Decrypt (0xe5e0) — 100% 确认（列换位）
栏数: `C = (sum(key) % 5 + slen) % 5 + 2`  (sum = Σ key[i] 以 int 累加)
行数: `R = ceil(slen / C)`
列高: 前 `full = slen % C`（为 0 时取 C）列有 R 个字符，其余列 R-1 个。
密文按**列优先**填入 R×C 网格，按**行优先**读出。
```c
void Fence_Decrypt(const uchar* src, int slen, uchar* key, int klen, uchar* dst) {
    int sum = 0; for (int i=0;i<klen;i++) sum += key[i];
    int C = (sum % 5 + slen) % 5 + 2;
    int R = (slen + C - 1) / C;
    int full = slen % C; if (full == 0) full = C;
    int coff[C], acc = 0;
    for (int c=0;c<C;c++){ coff[c]=acc; acc += (c<full?R:R-1); }
    int out = 0;
    for (int r=0;r<R;r++)
      for (int c=0;c<C;c++)
        if (r < (c<full?R:R-1)) dst[out++] = src[coff[c]+r];
}
```
真值（key=0102...10, sum=136, sum%5=1）:
```
slen 2 -> AB            [0,1]              C=2
slen 3 -> ABC           [0,1,2]            C=2
slen 4 -> ACBD          [0,2,1,3]          C=2
slen 5 -> ACEBD         [0,2,4,1,3]        C=3
slen 6 -> ACEFBD        [0,2,4,5,1,3]      C=4
slen 7 -> ACEFGBD       [0,2,4,5,6,1,3]    C=5
slen 8 -> ACEFGHBD      [0,2,4,5,6,7,1,3]  C=6
slen 9 -> AFBGCHDIE     [0,5,1,6,2,7,3,8,4] C=2
slen 10-> AEHBFICGJD    [0,4,7,1,5,8,2,6,9,3] C=3
slen 11-> ADGJBEHKCFI   [0,3,6,9,1,4,7,10,2,5,8] C=4
slen 12-> ADGJBEHKCFIL  [0,3,6,9,1,4,7,10,2,5,8,11] C=5
slen 13-> ADFHJLBEGIKMC [0,3,5,7,9,11,1,4,6,8,10,12,2] C=6
slen 14-> AHBICJDKELFMGN [0,7,1,8,2,9,3,10,4,11,5,12,6,13] C=2
```
栏数公式交叉验证（slen=5）:
```
key=05/00/0a/0f/ff*16 (sum%5=0) -> ADBEC (C=2)
key=01 (sum%5=1) -> ACEBD (C=3)
key=02 (sum%5=2) -> ACDEB (C=4)
key=03/0102 (sum%5=3) -> ABCDE (C=5, 恒等)
key=04 (sum%5=4) -> ABCDE (C=6, 恒等)
```

### AES (AesSetKey 0xa390 / AesDecryptECB) — 100% 确认 = 标准 AES-128-ECB
`AesSetKey(AesCtx*, int a, int b, uchar* key, uchar* iv)`；a=0 → Nk=4/Nb=4/Nr=10 = AES-128；
b<=2 时对轮密钥做 InvMixColumns（解密密钥扩展）。标准 RCON 表 @0x13d80；T-table 实现。
NIST 真值（oracle 实测）:
```
aesecbdec 69c4e0d86a7b0430d8cdb78070b4c55a 000102030405060708090a0b0c0d0e0f
  -> 00112233445566778899aabbccddeeff        (FIPS-197 C.1) OK
aesecbdec 3ad77bb40d7a3660a89ecaf32466ef97 2b7e151628aed2a6abf7158809cf4f3c
  -> 6bc1bee22e409f96e93d7e117393172a        (SP800-38A ECB-AES128 blk1) OK
```
注: `AesDecryptECB` 要求 size 为 16 的倍数，否则行为未定义（decryptByPlan 依赖上层 padding）。

## KEY. 容器 TLV 格式 (oracle 端到端 100% 确认)

### 顶层结构
```
[header 6B]  [tag]*     // 按出现顺序排列，无显式总长
header = "KEY."(4B) + version(uint16 LE ∈ {1,2})
```
decrypt_parse (@0x2540) 用跳转表 @0x2900 按 `tagType` 分派：

| tagType  | idx | 解析函数             | 消耗字节                       |
|----------|-----|----------------------|--------------------------------|
| 0xffff   | 0   | hashTagRead @0xe0a0  | 18                             |
| 0x0000   | 1   | (不前进)             | 0                              |
| 0x0001   | 2   | encryptTagRead @0xdf00 | PlansLength + KeyLength + 7  |
| 0x0002   | 3   | tokenTagRead @0xe050 | 18                             |
| 0x0003   | 4   | expiresTagRead @0xdff0 | 26                           |
| 0x00ff   | —   | dataTagRead @0xdfa0  | length + 6                     |

### 各 tag 字节布局 (小端)
```
hashTag   18B: [0..2)tagType=0xffff  [2..18)hash16
encryptTag   : [0..2)tagType=1  [2]EncryptType  [3..5)PlansLength
               [5..5+PL)Plans  [5+PL..7+PL)KeyLength  [7+PL..7+PL+KL)Key
tokenTag  18B: [0..2)tagType=2  [2..18)token16 = MD5(ctx.token)
expiresTag26B: [0..2)tagType=3  [2..10)int64 expires(明文)
               [10..26)expiresData16 = encryptByPlan(le64(expires))
dataTag      : [0..2)tagType=0xff  [2..6)uint32 length  [6..6+len)data
```
零拷贝：各 Read 函数仅把结构体指针指向源缓冲区内部（`auto_add_memcpy_src` 自动推进游标）。

### 容器组装顺序 (encrypt_parse @0x22b0-0x253b)
```
header → encryptTag → [tokenTag(仅 useToken)] → expiresTag → dataTag → hashTag
总长 = dtLen + (encryptTagLen+6) + [tokenTagLen] + exLen + 18(hashTag)
```
`createHashTag` 覆盖**除 hashTag 外全部已写出字节**。

## createKey 密钥派生 (0xdc50) — oracle 真值全分支确认
```c
int createKey(encryptTag* e_tag, uint8_t* basekey, uint32_t keylen,
              int64_t expires, uint8_t* token, int useKey, uint8_t* out) {
    int klen = e_tag->KeyLength;
    size_t bufLen = (expires > 0) ? klen + 40 : klen + 16;
    uint8_t* buf = calloc(1, bufLen);
    memcpy(buf, e_tag->Key, klen);                    // 容器内 Key
    if (useKey) memcpy(buf + klen, basekey, keylen);  // ctx->key
    else        memcpy(buf, "752500f5fa6b6b8f", 16);  // 内置常量 @0xecbb
    if (expires > 0) {
        *(int64_t*)(buf + 0x20) = expires;            // 固定偏移 0x20 (与 klen 无关)
        memcpy(buf + 0x28, token, 16);                // 固定偏移 0x28
    }
    GetMd5(buf, bufLen, out);                         // 16B 输出
    free(buf); return 0;
}
```
真值（oracle 实测）:
```
createkey 00112233445566778899aabbccddeeff 16 <basekey> 16 0 <00*16> 1
  -> bccbf4000d0864a0c19278ae3e69da6c  = MD5(eKey||basekey)              ✓
createkey ... 0
  -> 0de326ce0333782aac0138808c3c3486  = MD5("752500f5fa6b6b8f"||00*16)  ✓
createkey ... 16 ... 1234567890 <token16> 1
  -> 8f9cb7e9d5acd862b98fff9a52d23d60  = MD5(eKey||basekey||le64(exp)||token) ✓
createkey ... 8 <basekey> 16 1234567890 <token16> 1
  -> db3d748980668551fc82c35fff1da0ab  = MD5(eKey[0:8]||basekey||00*8||le64(exp)||token[0:8]) bufLen=48 ✓
```

## createHashTag = MD5(SHA1_le(data)) (0xdb70)
```c
int createHashTag(hashTag* tag, uint8_t* data, size_t len) {
    SHA1Context ctx;                 // 栈 0x68 字节
    SHA1Reset(&ctx); SHA1Input(&ctx, data, len);
    if (SHA1Result(&ctx)) {
        uint8_t md5[16];
        GetMd5(&ctx, 0x14, md5);     // MD5 over SHA1Context 前 20B (小端字节序!)
        memcpy(tag->hash, md5, 16);
    }
    tag->tagType = 0xffff; return 0x12;
}
```
**关键**：`SHA1Context.Intermediate_Hash[5]` 是 `uint32` 数组，内存为**小端字节序**。
```
SHA1Context 布局 (SHA1Reset @0x8020):
  +0x00 uint32 Intermediate_Hash[5]   // 20B 摘要(host 小端)
  +0x18 uint32 Length_Low
  +0x1c uint32 Length_High
  +0x20 int16  Message_Block_Index
  +0x22 uint8  Message_Block[64]
  +0x60 int    Computed
  +0x64 int    Corrupted
```
真值: `sha1 616263` -> `363e99a96a81064771253eba6cc250789dd8d09c`
（标准 BE = `a9993e364706816aba3e25717850c26c9cd0d89d`，每 4 字节反序即得 LE）
`hashtag 616263` -> `18 ffff d72ab8b1ff198abca947dfe60a1e6147`
且 `MD5(363e99a9...9dd8d09c) = d72ab8b1ff198abca947dfe60a1e6147` ✓（LE 匹配，BE 不匹配）

## decrypt_parse 主流程 (0x2540-0x28bd) — 反汇编 100% 还原
```c
int decrypt_parse(Pasrser_CTX* ctx, unsigned char* data, int len) {
    /* r15=ctx, r13=data, r14d=len */
    if (*(uint32_t*)data != 0x2e59454b) return -2;        // "KEY." 魔数
    uint16_t v = *(uint16_t*)(data + 4);
    if ((uint16_t)(v - 1) > 1) return -3;                 // v ∈ {1,2}

    encryptTag et = {0}; dataTag dt = {0};
    tokenTag tk = {0}; expiresTag ex = {0}; hashTag ht = {0};
    uint8_t* p = data + 6; int count = 0;
    while (p - data < len) {
        if (count == 9) return -2;                        // 最多 9 个 tag
        int n;
        switch (*(uint16_t*)p) {                          // 跳转表 @0x2900
          case 0x0001: n = encryptTagRead(p, &et); break;
          case 0x0002: n = tokenTagRead(p, &tk);   break;
          case 0x0003: n = expiresTagRead(p, &ex); break;
          case 0xffff: n = hashTagRead(p, &ht);    break;
          case 0x00ff: n = dataTagRead(p, &dt);    break;
          default:     n = 0;                      break;
        }
        p += n; count++;
    }
    if (count > 8) return -2;                             // 实际约束: ≤8 个有效 tag

    uint8_t key16[16];
    createKey(&et, ctx->key, 0x10, ctx->expires, tk.token, ctx->useKey, key16);

    if (v == 2) {                                         // 仅 version 2 做三重校验
        if (ht.tagType != 0) {                            // hashTag 存在才校验
            hashTag nh = {0};
            createHashTag(&nh, data, len - 0x12);         // 除末尾 hashTag 外全部
            if (memcmp(nh.hash, ht.hash, 16) != 0) return -6;
        }
        if (tk.tagType != 0) {                            // tokenTag 存在才校验
            uint8_t md[16];
            GetMd5(ctx->token, ctx->tokenLen, md);
            if (memcmp(tk.token, md, 16) != 0) return -4;
        }
        int64_t ge = getExpires(ex, et, key16);
        if (ge != ex.expires)   return -5;                // 必须等于容器内明文 expires
        if (ge <  ctx->expires) return -5;                // 且不早于 ctx->expires
    }

    dataTag out = {0};
    getData(et, key16, dt.data, dt.length, &out);
    ctx->data = malloc(out.length);
    memcpy(ctx->data, out.data, out.length);
    ctx->length = out.length;
    free(out.data);
    return 0;
}
```

### 关键语义
- **tag 上限 9**：循环内 `count == 9` 即返回 -2；循环结束 `count > 8` 亦 -2（有效 tag ≤8）。
- **`v != 2` 跳过全部校验**：hash/token/expires 三重校验只在 version==2 时执行；version==1 直接 getData。
- **`tagType == 0` 跳过校验**：hashTag/tokenTag 结构未被填充（tagType 仍为 0）时跳过对应校验，不报错。
- **expires 双校验**：先 `getExpires(...) == ex.expires`（容器内明文），再 `>= ctx->expires`（调用方要求）。任一不满足返回 -5。

### getExpires (0xe0f0) / getData (0xe140)
```c
int64_t getExpires(expiresTag e, encryptTag et, uint8_t* key) {
    dataTag tmp = {0};
    decryptByPlan(&tmp, &et, key, (char*)e.expiresData, 16);
    int64_t r = -1;
    if (tmp.length == 8) { r = *(int64_t*)tmp.data; free(tmp.data); }
    return r;   // length != 8 时不 free（参考实现内存泄漏，不影响逻辑）
}

int getData(encryptTag et, uint8_t* key, uint8_t* src, size_t size, dataTag* out) {
    decryptByPlan(out, &et, (char*)key, (char*)src, (int)size);
    return 0;
}
```

错误码: `-2` 魔数/tag 超限 `-3` 版本 `-4` token `-5` expires `-6` hash 校验失败 `0` 成功

## encrypt_parse 容器组装 (0x22b0-0x253b)
```c
void encrypt_parse(Pasrser_CTX* ctx, uint8_t* data, int len) {
    if (!setSRand) { srand(time(0)); setSRand = 1; }
    header head; createHeader(&head);
    encryptTag et; int total = createEncryptTag(&et) + 6;
    tokenTag tk = {0};
    if (ctx->useToken) total += createTokenTag(&tk, ctx->token, ctx->tokenLen);
    uint8_t key16[16];
    createKey(&et, ctx->key, 16, ctx->expires, tk.token, ctx->useKey, key16);
    dataTag dt; int dtLen = createDataTag(&dt, &et, data, len, key16);
    expiresTag ex = {0}; ex.expires = ctx->expires;
    int exLen = createExpiresTag(&ex, &et, key16);
    int totalLen = dtLen + total + exLen + 0x12;
    ctx->length = totalLen;
    uint8_t* buf = malloc(totalLen); bzero(buf, totalLen);
    uint8_t* p = buf;
    headWriteInto(&p, head);
    encryptTagWriteInto(&p, et);
    if (ctx->useToken) tokenTagWriteInto(&p, tk);
    expiresTagWriteInto(&p, ex);
    dataTagWriteInto(&p, dt);
    hashTag ht = {0}; createHashTag(&ht, buf, p - buf);
    hashTagWriteInto(&p, ht);
    free(dt.data); ctx->data = buf;
}
```

## encryptByPlan / createXxx (加密方向, 0x6f80 + tag.c)

### encryptByPlan (0x6f80) — 正序 + PKCS#7
```c
void encryptByPlan(dataTag* tag, encryptTag* e_tag, char* key, const uint8_t* p_data, int size) {
    if (e_tag->EncryptType != 1) return;
    int paddedLen = (size + 0x0f) & ~0x0f;        // 向上取整到 16 的倍数
    uint8_t* buf = malloc(paddedLen);
    memset(buf, paddedLen - size, paddedLen);     // PKCS#7: 先全部填 pad 值
    memcpy(buf, p_data, size);                    // 再覆盖明文
    for (int idx = 0; idx < e_tag->PlansLength; idx++) {   // 正序! (解密为逆序)
        signed char planByte = e_tag->Plans[idx];
        signed char sel = PLANS_DIC[planByte];
        if ((unsigned)sel > 3) continue;
        switch (sel) {
          case 0: Caesar_Encrypt(buf, paddedLen, key, 16, buf); break;
          case 1: my_RC4(buf, paddedLen, key, 16); break;
          case 2: Fence_Encrypt(buf, paddedLen, key, 16, buf); break;
          case 3: { AesCtx c; AesSetKey(&c,0,0,key,0); AesEncryptECB(&c,buf,buf,paddedLen); } break;
        }
    }
    tag->data = buf; tag->length = paddedLen;
}
```
跳转表 @0x7128: case0=0x708f Caesar_Encrypt / case1=0x70b0 my_RC4 / case2=0x70d0 Fence_Encrypt / case3=0x7020 AES-ECB。

### createEncryptTag (0xd9e0)
```c
int createEncryptTag(encryptTag* tag) {
    tag->tagType = 1; tag->EncryptType = 1;
    int pl = rand() % 5 + 4;             // PlansLength ∈ [4,8]
    tag->PlansLength = pl;
    tag->Plans = malloc(pl);
    for (int i = 0; i < pl; i++) tag->Plans[i] = rand() % 32;   // 0..31
    tag->KeyLength = 16;
    tag->Key = malloc(16);
    createPartKey(tag->Key, 16);         // rand 填充
    tag->length = pl + 16 + 7;           // PlansLength + KeyLength + 7
    return tag->length;
}
```
注：`Plans[i] ∈ [0,31]`，故解密端 `PLANS_DIC[planByte]` 永不越界（不存在负索引）。

### createDataTag (0xdab0)
```c
int createDataTag(dataTag* tag, encryptTag* e_tag, uint8_t* data, uint32_t size, uint8_t* key) {
    tag->tagType = 0xff;
    encryptByPlan(tag, e_tag, key, data, size);
    return tag->length + 6;              // +6 = tagType(2) + length(4)
}
```

### createExpiresTag (0xdae0)
```c
int createExpiresTag(expiresTag* tag, encryptTag* e_tag, uint8_t* key) {
    dataTag tmp = {0};
    encryptByPlan(&tmp, e_tag, key, (uint8_t*)&tag->expires, 8);  // 8B 明文 → 16B
    tag->tagType = 3;
    memcpy(tag->expiresData, tmp.data, 16);
    free(tmp.data);
    return 0x1a;                         // 26
}
```

### createTokenTag (0xdb40)
```c
int createTokenTag(tokenTag* tag, uint8_t* token, int32_t len) {
    tag->tagType = 2;
    GetMd5(token, len, tag->token);      // token 的 MD5, 16B
    return 0x12;                         // 18
}
```

## 端到端真值样本 (oracle 实测, 152B 容器)
输入: plain=`"hello koolearn decrypt world! 0123456789"`, ctxkey=`"5wqPBk89IkGBxXZy"`,
useKey=1, useToken=1, token=`"user-12345678"`, expires=1234567890
```
container(152B) =
  4b45592e 0200                                             header "KEY." v2
  0100 01 0700 1303061614081e 1000 0889b418c7bdf710c893be20b634d434   encryptTag
  0200 08ef95d65cd2fb140bdfd0fe29b45979                     tokenTag = MD5("user-12345678")
  0300 d202964900000000 abe8fd8babb2a9386f9f0efe2c3ae421        expiresTag
  ff00 30000000 42d76f1a...88953                            dataTag(48B)
  ffff 2ac2a287b30a000bb2a44cdfe7a6c38a                     hashTag

decryptparse -> 0 40 68656c6c6f206b6f6f6c6561726e206465637279707420776f726c64212030313233343536373839
  (40B 明文完全匹配 ✓)
hash 独立复算: MD5(SHA1_le(前134B)) = 2ac2a287b30a000bb2a44cdfe7a6c38a ✓
```

## 待还原 (下一步)
- [x] createKey: MD5 派生细节 (basekey+token+expires → 16B key)
- [x] decrypt_parse: KEY. 容器 TLV 解析顺序 + tagType 常量值
- [x] encrypt_parse: 容器构造 (用于 harness 造真值样本)
- [ ] Go 复刻全部流程 + 大规模随机样本交叉验证
