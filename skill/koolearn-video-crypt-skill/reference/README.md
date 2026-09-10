# reference/ —— 逆向用原始样本（只读）

本目录存放逆向分析的**原始二进制与调试符号**，是 `docs/decrypt-node-reverse.md`
与 `internal/kcrypt/`（Go 复刻）的**可复现来源**。这些文件不参与构建，仅供研究比对。

> ⚠️ 仅供安全研究与互操作性分析。请勿用于绕过版权保护或再分发受版权保护的内容。

> 📦 **本 skill 未附带二进制样本**：`decrypt.node` 及其 `decrypt.node.dSYM/` 因体积与
> 分发原因被排除，仅保留 JS 包装层（`main.js` / `package.json`）。需要样本时，请从你本机
> 已安装客户端的 `app.asar`（`node_modules/koolearn-decrypt/`）自行解包获取；下方第 3 节的
> sha256 / UUID 用于确认你取得的是同一条构建产物。缺失该二进制时，依赖它的 oracle 对拍测试
> 会自动跳过（`t.Skipf`），不影响构建与其余测试。

## 1. 文件清单

| 文件 | 大小 | 说明 |
|---|---|---|
| `koolearn-decrypt/decrypt.node` | 124 696 B | Node 原生扩展（Mach-O 64-bit bundle，**x86_64**，符号未 strip） |
| `koolearn-decrypt/decrypt.node.dSYM/` | 392 K | 与之配套的 dSYM 调试信息（含完整 DWARF：函数名/参数/类型/结构体） |
| `koolearn-decrypt/main.js` | 183 B | 包入口，导出 `decrypt(data, key, token, expires)` |
| `koolearn-decrypt/package.json` | 258 B | `name=koolearn-decrypt`，`version=0.3.3` |

## 2. 来源

- 取自 **koolearn 桌面客户端**（`koolearncg` v5.1.4，appid `com.koolearn.wm`，
  产品名「新东方大学考试」）的 `app.asar` 解包结果：
  `app/node_modules/koolearn-decrypt/`。
- `decrypt.node` 与 `decrypt.node.dSYM` 由构建机
  `/Users/Shared/work/yd-jenkins/workspace/neibu-wm-daxue-koolearn/` 产出
  （路径见 DWARF `DW_AT_decl_file`），dSYM 被一并打包进了 asar。
- `package.json` 声明 `version=0.3.3`，依赖 `nan ^2.14.0`。

## 3. 校验（sha256）

```
1ec9fefcdd7145d88952dfc6fd4de3c815486548cc0c1d37f8909a696f9b98e3  decrypt.node
54de166b8dadf7d4081771ee163721c8ff83b5453a922bafa0cac7997564410f  main.js
9c262f2f4f4fed0093fb50c05352235ad12cff3db577905b04a522741329c96a  package.json
```

dSYM 与二进制 UUID 一致（证明是同一构建产物）：

```
B30B89C4-1619-3A20-B244-6DD4C5886D27 (x86_64)
```

复核命令：

```bash
shasum -a 256 reference/koolearn-decrypt/decrypt.node
dwarfdump --uuid reference/koolearn-decrypt/decrypt.node
dwarfdump --uuid reference/koolearn-decrypt/decrypt.node.dSYM
```

## 4. 这些样本怎么用

| 用途 | 命令 / 入口 |
|---|---|
| 提取全部符号（函数签名/参数/类型/结构体） | `python3 scripts/dwarf-functions.py > docs/dwarf-functions.txt` |
| 作为 dlopen oracle 被 harness 驱动 | `bash harness/build.sh && ./harness/oracle`（见 `harness/oracle.c`） |
| Go 复刻对拍验证 | `go test ./internal/kcrypt/ -count=1` |

> 主机为 arm64 时，`decrypt.node`（x86_64）通过 **Rosetta 2** 运行。
