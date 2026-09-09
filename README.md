# koolearn-crypt

> 新东方在线桌面客户端（`koolearncg` / "新东方大学考试"）的**下载与私有加密方案**逆向分析文档。
>
> 本仓库当前阶段**只做研究与文档记录，不含任何实现代码**（先不动工）。
> 目标是把 App 的 HLS 视频下载、本地存储结构、`koolearn-decrypt` 私有加密算法彻底梳理清楚，
> 为后续「离线内容导出 / 格式转换」等工具的实现提供完整的技术依据。

---

## 目录

- [0. 合规与免责声明](#0-合规与免责声明)
- [1. App 概览](#1-app-概览)
- [2. 整体架构](#2-整体架构)
- [3. 下载子系统](#3-下载子系统)
  - [3.1 HLS 视频下载（koolearn-download + aria2c）](#31-hls-视频下载koolearn-download--aria2c)
  - [3.2 普通文件下载（Electron will-download）](#32-普通文件下载electron-will-download)
- [4. 下载存储位置与目录结构](#4-下载存储位置与目录结构)
- [5. 私有加密方案（koolearn-decrypt）](#5-私有加密方案koolearn-decrypt)
  - [5.1 模块与 API](#51-模块与-api)
  - [5.2 `KEY.` 容器格式](#52-key-容器格式)
  - [5.3 密钥派生](#53-密钥派生)
  - [5.4 `decryptByPlan` 多轮组合算法](#54-decryptbyplan-多轮组合算法)
  - [5.5 PLANS_DIC 字典与跳转表](#55-plans_dic-字典与跳转表)
  - [5.6 密码原语清单](#56-密码原语清单)
  - [5.7 渲染层调用链（定制 hls.js）](#57-渲染层调用链定制-hlsjs)
- [6. 播放流程（local.m3u8）](#6-播放流程localm3u8)
- [7. 导出为 MP4 的可行性评估](#7-导出为-mp4-的可行性评估)
- [8. 逆向工程记录（符号 / 地址速查）](#8-逆向工程记录符号--地址速查)
- [9. 后续 TODO（先不动工）](#9-后续-todo先不动工)

---

## 0. 合规与免责声明

- 本项目仅用于**个人学习与安全研究**，分析对象为用户本地已合法安装的客户端。
- App 内的视频/课件受版权与 DRM 保护，导出行为可能违反**服务条款（ToS）**及相关法律法规。
- 任何基于本文档的实现，请仅在**已获授权 / 自有内容**的前提下使用，风险自担。

---

## 1. App 概览

| 项 | 值 |
|---|---|
| 包名（package.json `name`） | `koolearncg` |
| 版本 | `5.1.4` |
| 入口 | `./main/main.js`（Electron 主进程） |
| 运行时 | Electron（Chromium + Node.js） |
| `global.appname` | `koolearn`（在 `main.js:38` 设置，决定数据目录名） |
| `appid` | `com.koolearn.wm` |
| `gappname` | `新东方大学考试` |
| macOS 安装路径 | `/Applications/新东方大学考试.app` |
| `app.asar` MD5 | `33b167d692358d39fff38351cfe407b3`（28,989,758 字节） |

**关键原生依赖（node_modules）：**

| 模块 | 版本 | 作用 |
|---|---|---|
| `koolearn-download` | `0.7.3` | "a hls download manager"，基于 aria2c 的 m3u8 分片下载器 |
| `koolearn-decrypt` | `0.3.3` | C++/NAN 原生插件（`decrypt.node`），私有解密算法 |
| `koolearn-m3u8-parser` | — | m3u8 解析 |
| `nedb` | — | 嵌入式 NoSQL（settings.db / download.db / keys.db / index.dl） |

**渲染层：** `dist/bundle.js`（约 6.7 MB / 786 行压缩代码），内含**定制版 hls.js**（`isKoolearn` / `isKoolearnET` 标记）。

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Electron App                          │
│                                                              │
│  ┌──────────────────┐         ┌───────────────────────────┐ │
│  │   主进程 (Node)   │  IPC    │      渲染进程 (Chromium)    │ │
│  │  main/main.js     │◄───────►│  dist/bundle.js           │ │
│  │  main/session.js  │         │   ├─ 定制 hls.js          │ │
│  │  main/lectures.js │         │   └─ 业务 UI              │ │
│  └────────┬─────────┘         └────────────┬──────────────┘ │
│           │                                 │ remote.require │
│           │                                 ▼                │
│           │                    ┌────────────────────────┐   │
│           │                    │ koolearn-decrypt (.node)│   │
│           │                    │  私有解密原生模块        │   │
│           │                    └────────────────────────┘   │
│           │                                                  │
│  ┌────────▼─────────────────────────────────────────┐      │
│  │ koolearn-download (Node 模块)                     │      │
│  │   downloadManager → Queue(5) → hlsDownloader      │      │
│  │        └─► aria2c (JSON-RPC @127.0.0.1:随机端口)   │      │
│  └───────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

App 存在**两套并行的下载机制**：

1. **HLS 视频下载** —— 走 `koolearn-download` + `aria2c`，下载加密的 `.ts` 分片，落盘后由播放器实时解密。
2. **普通文件下载**（PDF/讲义/附件等）—— 走 Electron 原生 `will-download`，配合 `session.js` 注入响应头。

---

## 3. 下载子系统

### 3.1 HLS 视频下载（koolearn-download + aria2c）

**模块结构（`node_modules/koolearn-download/src/`）：**

| 文件 | 行数 | 职责 |
|---|---|---|
| `downloadManager.ts` | — | 单例；`Queue(concurrency: 5)`；`create()` 对 `Hls` 类型 `new hlsDownloader` |
| `hlsDownloader.ts` | 662 | HLS 下载核心（见下方流程） |
| `aria2c.ts` | 317 | aria2c 引擎封装（JSON-RPC 控制） |
| `queue.ts` | 217 | 并发队列 |
| `m3u8.ts` | — | m3u8 解析/改写 |
| `database.ts` | — | nedb 持久化（`index.dl` 分片进度） |
| `utility.ts` | 270–335 | `httpEx.getText/get`（node-fetch）；`http.checkJson` 检测密钥是否返回 JSON 错误 |
| `downloadStatus.ts` / `downloadType.ts` / `downloadEvents.ts` / `downloadError.ts` | — | 状态机 / 类型 / 事件 / 错误定义 |

**`hlsDownloader.start()` 流程：**

```
start()
  ├─ loaddl()          # 读取 index.dl，断点续传已完成分片
  ├─ getM3u8()         # 拉取 index.m3u8（playlist）
  ├─ 下载 key          # 拉取密钥块 → 写入 vodkey.bin
  └─ 逐分片下载:
       await aria2c.open()                       # 启动 aria2c 进程 + JSON-RPC 监听
       const gids = await aria2c.addUri(segment.url, segmentPath)
       this.gid = gids[0][0]
       sucess = await aria2c.wait(this.gid)       # 等待该分片完成
     ...
     最后校验 .ts 数量是否与 playlist 一致
```

**`aria2c.ts` 引擎要点：**

```js
// 启动参数
const args = [
  `--rpc-listen-port=${this._port}`,   // 随机端口
  "--enable-rpc",
  "--rpc-allow-origin-all",
  "--allow-overwrite",
  '--remove-control-file=true',        // 不保留 .aria2 控制文件
];
const proxy = process.env["KOOLEARN-DOWNLOAD-PROXY"];  // 可选代理
```

- 二进制路径：`bin/{platform}/{arch}/aria2c`；**darwin 仅提供 x64**（3.6 MB）。
- 控制方式：JSON-RPC over HTTP，`127.0.0.1:{随机端口}/jsonrpc`。

**要点：** 下载下来的 `.ts` 分片是**密文**，`koolearn-download` 本身**不做解密**，解密发生在播放时（见 §5、§6）。

### 3.2 普通文件下载（Electron will-download）

**`main/main.js`（470–568 行）：**

| 位置 | 函数 | 作用 |
|---|---|---|
| L38 | — | `global.appname = 'koolearn';`（决定数据目录名，**关键**） |
| L526 | `webContentDownload` | 注册 `will-download` 并触发 `downloadURL` |
| L538 | `webContentWillDownload` | 监听 `updated` / `done` 事件 |
| L565 | `webContentSendStatus` | 通过 IPC 回传 `(url, status, receivedBytes, totalBytes)` |

IPC 通道：`newDownloadTask`、`webContentDownload`。

**`main/session.js`：**

- `onHeadersReceived`：注入 `Content-Disposition`（处理 `attachmentPdf` / `attachmentFileName`，读取自定义头 `xdf-download-filename`）。
- `onBeforeRequest`：强制 HTTPS（`vdn.*.koopass.com`）。
- 改写 `User-Agent`。

**`main/lectures.js`（内容脚本）：**

- 拦截 `.j-operate-download` 点击 → 追加 `xdf-download-filename` → `window.open` 触发下载。

---

## 4. 下载存储位置与目录结构

### 4.1 根路径推导

```
getAppPath()          # bundle.js @5932091
  darwin  = [HOME, "Library/Application Support/", appname, appname, ...]
  appname = "koolearn"（来自 main.js:38 的 global.appname）

getDefaultSettings()  # bundle.js @5949592
  const e = join(getAppPath(), "download")
  downloadSetting: { path: e, isAuto: true, definition: "" }
```

**各平台默认下载根目录：**

| 平台 | 路径 |
|---|---|
| macOS | `~/Library/Application Support/koolearn/koolearn/download/` |
| Windows | `%APPDATA%\koolearn\koolearn\download\` |

> 注意路径里 **`koolearn/koolearn` 重复两层**：外层是 `getAppPath()` 的固定结构，内层是 appname。

### 4.2 用户机器实测

```
~/Library/Application Support/koolearncg/     # Electron userData（Cache/Cookies/…）
~/Library/Application Support/koolearn/koolearn/
    ├─ appstatistic
    ├─ cache
    │    └─ 110607776/settings.db            # 按 user_id 分目录
    └─ download/                             # 空（该机器尚未下载过视频）

cache/110607776/settings.db 内容:
    downloadSetting.path = "/Users/ariakage/Library/Application Support/koolearn/koolearn/download"
    definition = "HD"
    isAuto = true
    download.db / keys.db 均 0 字节（未下载过）
```

### 4.3 单个视频的目录命名

```js
// getPath() @ bundle.js 6000813
t = (yield getSettings()).downloadSetting.path;
n = `${productId.toString(32)}${orderNo}${courseId.toString(32)}${nodeId.toString(32)}`;
path = join(t, n);
```

即：`productId`、`courseId`、`nodeId` 转 **32 进制**，与 `orderNo` 拼接成一个子目录名。

**子目录内文件构成：**

| 文件 | 说明 |
|---|---|
| `index.m3u8` | 原始 playlist（分片列表 + `#EXT-X-KEY`） |
| `vodkey.bin` | 下载下来的**密钥块**（`KEY.` 容器格式，见 §5.2） |
| `*.ts` | **加密的**视频分片（密文） |
| `index.dl` | nedb，分片下载进度（断点续传） |
| `local.m3u8` | 播放用改写版（key URI 指向本地 `vodkey.bin`，见 §6） |

### 4.4 修改下载路径

- UI：设置 → 下载路径 → 浏览（`selectDirectory` @ bundle.js 6545814，`remote.dialog.showOpenDialog({properties:["openDirectory"]})`）。
- 持久化：按 `user_id` 存于 nedb `settings.db` 的 `downloadSetting.path`。

---

## 5. 私有加密方案（koolearn-decrypt）

> 对 `node_modules/koolearn-decrypt/build/Release/decrypt.node`（Mach-O x86_64，**符号未 strip**）的完整逆向结论。
>
> **它不是 CryptoPP**，而是**手写 AES + MD5 + 三种古典密码的多轮组合**自定义方案。

### 5.1 模块与 API

`koolearn-decrypt/main.js`：

```js
libdecrypt = require('./build/Release/decrypt.node');
module.exports.decrypt = function (data, key, token, expires) {
    return libdecrypt.decrypt(data, key, token, expires);
};
```

**`decrypt(data, key, token, expires)` 四个参数：**

| 参数 | 类型 | 含义 |
|---|---|---|
| `data` | Buffer | `KEY.` 容器密文（即 `vodkey.bin` 内容 / 密钥块） |
| `key` | Buffer | 硬编码盐：ET 变体为 `"5wqPBk89IkGBxXZy"`，否则为空 Buffer |
| `token` | Buffer | 用户 token（`user_id`） |
| `expires` | Integer | 时间戳；与魔数 `0x58D10EEF` 比较（方案分支开关） |

返回：`{ code, result }`（`CreateResult` @0x1a70 用 `v8::Integer::New` + `node::Buffer::Copy` + `Object::Set` 组装）。

### 5.2 `KEY.` 容器格式

`createHeader` @0x7440（极短）：

- 写入 4 字节魔数 `0x2e59454b`（小端 = ASCII **`KEY.`**）
- 紧接 2 字节 **version = 2**

因此 `vodkey.bin` 是一个 **`KEY.` 开头的 TLV 容器**。`decrypt_parse` @0x2540 负责解析它，按标签抽取字段：

| 标签读写函数 | 字段 |
|---|---|
| `create/read/writeIntoEncryptTag` | 加密数据体 |
| `create/readDataTag` | data |
| `create/readTokenTag` | token |
| `create/readExpiresTag` | expires（8 字节整数） |
| `create/readHashTag` | 校验哈希 |

`getData` / `getExpires` 都通过 `decryptByPlan` 按标签抽取对应字段。

### 5.3 密钥派生

`createKey` @0xdc50：

```
拼接 data (+ token) 缓冲区
  → GetMd5()
  → MD5 输出 16 字节  = AES 密钥
  → 另有 16 字节 IV
```

`createPartKey` @0x7400：用 `rand() + 1` 填充随机字节（**加密侧**生成盐用；解密侧不参与）。

> 即最终 AES 密钥 = `MD5(data ‖ token)` 的 16 字节摘要。`key`（硬编码盐）与 `expires` 参与 `Method` 的分支判定与容器解析。

### 5.4 `decryptByPlan` 多轮组合算法

`decryptByPlan` @0x7140 是核心解密器，逻辑为**多轮组合**：

```
输入: blob（KEY. 容器内加密数据体）
轮数 rounds = blob[+8] 处的 16-bit 值

for round in 0..rounds-1:
    1) AES-ECB 整块解密（用派生出的 16 字节 key）
    2) 取 plan[round] → 查 PLANS_DIC 字典 → 得到密码选择子 sel ∈ {0,1,2,3}
    3) 按 sel 走跳转表，选一种古典/流密码再处理一遍（均用 16 字节 key）:
         sel=0 → Caesar_Decrypt   (凯撒)
         sel=1 → my_RC4           (RC4)
         sel=2 → Fence_Decrypt    (栅栏)
         sel=3 → 0x71e0           (另一种，待确认)

最后: PKCS#7 去填充
结果结构: { len @ +4, data @ +8 }
```

### 5.5 PLANS_DIC 字典与跳转表

**`PLANS_DIC` @0xed30**（32 字节查找表，把每轮的 plan 字节映射成密码选择子 0–3）：

```
03 01 00 00 03 00 02 03 03 01 03 03 01 01 01 02
03 03 00 02 00 00 01 02 03 00 03 03 02 00 01 03
```

**跳转表 @0x737c**（4 项，相对基址）：

| sel | 目标 |
|---|---|
| 0 | `Caesar_Decrypt` |
| 1 | `my_RC4` |
| 2 | `Fence_Decrypt` |
| 3 | `0x71e0`（待确认具体算法） |

### 5.6 密码原语清单

| 类别 | 函数 |
|---|---|
| 手写 AES | `aes_gen_tables` / `aes_set_key` / `KeyExpansion` / `SubWord` / `RotWord_Right` / `InvMixColumnsDecKey`；模式 `ECB / CBC / PCBC / CRT(CTR) / CFB / OFB`；S-box @0xed80（标准 `63 7c 77 7b f2 6b …`） |
| 流密码 | `my_RC4` / `re_RC4` |
| 古典/混淆 | `Caesar_Encrypt/Decrypt`（凯撒）、`Fence_Decrypt`（栅栏）、`XOR2_64`、`padding` |
| 哈希 | `GetMd5` + MD5、SHA1 |
| 密钥/编排 | `decryptByPlan`、`createKey`、`createPartKey`、`createHeader` |
| TLV 标签 | `create/read/writeInto` × `Encrypt/Data/Expires/Token/Hash` Tag |
| 导入 stub | `malloc`(0xe9be) / `free`(0xe9b8) / `memcpy`(0xe9ca) / `memset`(0xe9d0) / `rand`(0xe9d6) / `srand`(0xe9dc) / `time`(0xe9e2) / `IntegerValue`(0xe988) / `Buffer::Data`(0xe97c) / `Buffer::Length`(0xe982) |

### 5.7 渲染层调用链（定制 hls.js）

**解密核心 @ bundle.js 943494**（hls.js `loadsuccess` 回调，即密钥块下载成功后）：

```js
d = l.isKoolearnET ? Buffer.from("5wqPBk89IkGBxXZy") : Buffer.from(""),
h = Buffer.from(this.hls.userConfig.token || ""),
p = this.hls.userConfig.timestamp,
f = require("electron").remote.require("koolearn-decrypt").decrypt(c, d, h, p);
if (l.isKoolearnET)
    u = this.createMuitKeys(f.result.toString("utf8"), "initSegment" === s.sn ? 0 : s.sn);
```

- `c` = 下载到的密钥块（`KEY.` 容器密文）。
- `f.result` = 解密后的明文密钥串。
- ET 变体进一步调 `createMuitKeys` 展开**多密钥**。

**`createMuitKeys` @ bundle.js 944520**：把明文解析为 `[min,max]key;...` 形式的 **MutiKey 映射**（不同分片区间用不同密钥）。

**其它相关位置：**

| 位置 | 内容 |
|---|---|
| @5929287 | `wt.appname = getGlobal("appname")`，`appid="com.koolearn.wm"`，`gappname="新东方大学考试"` |
| @5932091 | `getAppPath()`（darwin 路径拼接） |
| @5949592 | `getDefaultSettings()`（默认下载路径） |
| @6000813 | `getPath()`（单视频目录命名，见 §4.3） |
| @6007059 | `invalidM3u8`：`KOOLEARN_M3U8_INVALID_TIME \|\| 3e5`（**5 分钟过期**） |
| @6545814 | `selectDirectory`（下载路径选择对话框） |

> 另存在 **WASM 解密路径**（备用），主路径为上述原生 `decrypt.node`。

---

## 6. 播放流程（local.m3u8）

```
1. 下载阶段:
   index.m3u8 + vodkey.bin + 加密 *.ts  →  落到 §4.3 的视频子目录

2. 播放阶段（createMediaUrl）:
   生成 local.m3u8：把原 playlist 里的 key URI 改写为指向本地 vodkey.bin
   以 file:// 方式喂给定制 hls.js

3. hls.js 加载 vodkey.bin（密钥块）→ loadsuccess:
   调 koolearn-decrypt.decrypt(c, d, h, p) 解出明文密钥
   ET 变体再 createMuitKeys 展开每段密钥

4. 逐 .ts 分片:
   用对应密钥（AES-128-CBC，IV=分片序号 或多密钥表）解密
   → 送入 MSE 播放

5. 时效:
   invalidM3u8 判定 5 分钟过期（KOOLEARN_M3U8_INVALID_TIME），过期需重新拉取
```

**关键结论：** 磁盘上的 `.ts` 始终是密文，**解密只发生在播放时的内存中**，密钥由 `koolearn-decrypt` 现场派生，不落明文。

---

## 7. 导出为 MP4 的可行性评估

直接用 `ffmpeg` 处理磁盘文件**不可行**——因为 `.ts` 是私有加密的密文，且密钥不在磁盘上（播放时由原生模块现场派生）。

| 方案 | 思路 | 难度 | 评价 |
|---|---|---|---|
| **A. 运行时 dump 密钥** | Hook `koolearn-decrypt.decrypt`，在 App 播放时把真实密钥/多密钥表导出，再离线解密合并 | 中 | **最实际**，绕开算法细节 |
| B. 标准 AES-128 分支 | 若某些内容走标准 HLS AES-128（IV=序号），可直接解密 | 低 | 仅适用于非私有加密内容 |
| C. 完整逆向 decrypt.node | 复刻 `decryptByPlan` 多轮组合算法，独立离线派生密钥 | 高 | 本文档已完成大部分，尚差 sel=3 与字节级细节 |
| D. 录屏兜底 | 播放时屏幕/音频采集 | 低 | 质量损失，最后手段 |

**方案 A 推荐流程：**

```
hook decrypt()  →  按分片序号收集每段 key（含 createMuitKeys 多密钥）
   →  openssl aes-128-cbc -d 逐段解密 .ts
   →  ffmpeg concat 封装为 .mp4
```

---

## 8. 逆向工程记录（符号 / 地址速查）

`decrypt.node`（Mach-O x86_64，未 strip）：

| 符号 | 地址 | 说明 |
|---|---|---|
| `Method` | 0x1be0 | JS 入口（NAN_METHOD），校验 argc>3，expires 与 `0x58D10EEF` 比较 |
| `Init` | 0x1ef0 | 模块注册 |
| `CreateResult` | 0x1a70 | 组装 `{code, result}` 返回对象 |
| `decrypt_parse` | 0x2540 | 解析 `KEY.` 容器 + 派生密钥（核心校验） |
| `parse_release` | 0x2920 | 释放解析上下文 |
| `decryptByPlan` | 0x7140 | 多轮组合解密核心 |
| `createKey` | 0xdc50 | `MD5(data‖token)` → 16B AES key + 16B IV |
| `createPartKey` | 0x7400 | `rand()+1` 填充随机字节 |
| `createHeader` | 0x7440 | 写 `KEY.` 魔数 + version=2 |
| `getExpires` | 0xe0f0 | 抽取 expires（8B 整数） |
| case3 目标 | 0x71e0 | PLANS_DIC sel=3 对应算法（待确认） |
| `PLANS_DIC` | 0xed30 | 32B 查找表（plan 字节 → 选择子 0–3） |
| 跳转表 | 0x737c | 4 项：Caesar / RC4 / Fence / 0x71e0 |
| AES S-box | 0xed80 | 标准 S-box |

**关键魔数：**

| 魔数 | 含义 |
|---|---|
| `0x2e59454b` | ASCII `KEY.`（容器头，小端） |
| version `2` | 容器版本（2 字节） |
| `0x58D10EEF` | Unix 时间 2017-03-13，`Method` 中的方案/版本分支开关 |
| `"5wqPBk89IkGBxXZy"` | ET 变体硬编码盐（16 字节） |

**逆向工具链：** Apple `objdump`（LLVM）+ `otool` + `nm`（无 radare2/ghidra，符号未 strip 故足够）。

---

## 9. 后续 TODO（先不动工）

> 当前阶段仅完成仓库创建与本文档。以下为实现阶段的候选方向，**待确认后再开工**：

- [ ] **方案 A**：编写 `decrypt` hook 脚本，运行时 dump 真实密钥 / 多密钥表。
- [ ] **方案 A**：编写「解密 `.ts` + `ffmpeg` 合并为 `.mp4`」的完整脚本。
- [ ] **方案 C**：补全 `decryptByPlan` 字节级细节，确认 `sel=3`（0x71e0）算法，复刻离线密钥派生。
- [ ] 校验 `KEY.` 容器的完整 TLV 字段布局（各 tag 的 type/length/value 编码）。
- [ ] 补充 `koolearn-m3u8-parser` 的解析细节。
- [ ] （可选）WASM 解密路径的逆向。

---

*本文档由对 `app.asar`（`koolearncg` v5.1.4）的静态分析与 `decrypt.node` 逆向整理而成，仅供研究参考。*
