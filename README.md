# dis_avb_reimpl — Unisoc/SPRD `dis_avb` patch 逻辑复刻

对 [TomKing062/action_spd_dump_it](https://github.com/TomKing062/action_spd_dump_it) 中 `dis_avb` 命令（进入 FDL2 后自动 patch **trustos 与 sml** 分区）所用算法的开源复刻，提供 **Python / C++ / Windows exe** 三种实现，输出与原版 C 工具逐字节一致。

> ⚠️ **声明**：`dis_avb` 命令本体在 `spd_dump_it` 闭源主程序中，本仓库是根据该工具链的公开源码（`gen_tos-noavb.c`、`chsize.c`、`chsize_update_sha256.c`、`bsp_sign_fxxker.c`）逆向复刻的算法实现。仅供安全研究/学习使用，请遵守当地法律与设备厂商条款。

---

## 背景：dis_avb 在做什么

`dis_avb`（Disable AVB）绕过 Unisoc 芯片的 pre-verification 签名校验（`SPL/FDL1 → UBOOT/FDL2` 启动链上的 BSP 检查）。整体流程：

```
输入: sml_or_teecfg（原始已签名文件，作"签名载体"）+ tos（trustos 镜像）
  ① gen_tos 算法: 扫描 trustos 的 AArch64 指令, 把校验函数的
     "mov x0, sp" 改为 "mov w0, #0"（返回值恒为 0 = 校验通过）
  ② chsize 算法:  按 DHTB footer（sprdsignedimageheader）计算并截断镜像真实大小
  ③ bsp_sign_fxxker: 用 sml 的原始签名包裹 patch 后的 trustos（Two-image 方法）
输出: tos-noavb-bsp-bypassed
```

对应上游源码：

| 复刻函数 | 上游源码 |
|---|---|
| `gen_tos_noavb()` | `action_spd_dump_it/gen_tos-noavb.c` |
| `chsize_old()` | `action_spd_dump_it/chsize.c`（旧式 footer 判定） |
| `dhtb_data_size()` | `action_spd_dump_it/chsize_update_sha256.c` |
| `bsp_sign_fxxker()` | `unisoc_chipram_signcheck_exploit/Patch-Pre-Verification/bsp_sign_fxxker.c` |
| `patch_code_uboot()` | `.../bsp_sign_fxxker_for_uboot.c` |

关键常量：DHTB magic `0x42544844`("BTHD")、RET `0xD65F03C0`、STP/LDP x29,x30 掩码 `0xA9007BFD`/`0xA8007BFD`、patch 值 `mov w0,#0 = 0x52800000`。

---

## 文件清单

```
dis_avb.py     Python 复刻（无第三方依赖, Python 3）
dis_avb.cpp    C++ 复刻（C++17, 无外部依赖）
dis_avb.exe    Windows 可执行文件（mingw-w64 交叉编译）
gen_test_images.py  合成测试镜像生成器
verify.sh      三套实现对照验证脚本（需 gcc/g++）
```

## Python 版

```bash
# 完整 dis_avb 流程: 等价于 spd_dump_it 里的 "dis_avb_ex sml_or_teecfg tos"
python3 dis_avb.py dis_avb <sml_or_teecfg.bin> <tos.bin> [输出文件]

# 单独步骤
python3 dis_avb.py gen_tos <tos.bin> [输出]      # ① → tos-noavb.bin
python3 dis_avb.py chsize <文件.bin>              # ② 截断(原地)
python3 dis_avb.py fxxker <签名载体> <修改后> <out> # ③ 签名包装
```

默认输出 `tos-noavb-bsp-bypassed`。

## C++ 版

```bash
g++ -O2 -std=c++17 -o dis_avb dis_avb.cpp
./dis_avb dis_avb <sml_or_teecfg.bin> <tos.bin> [输出文件]
# 子命令与 Python 一致: gen_tos / chsize / fxxker / dis_avb / uboot
```

## Windows exe

```bat
dis_avb.exe dis_avb sml_or_teecfg.bin tos.bin tos-noavb-bsp-bypassed
```

exe 由 `dis_avb.cpp` 用 mingw-w64 交叉编译，无运行库依赖（静态链接），双击/命令行均可。

## 如何选择签名载体：sml 还是 teecfg？

`dis_avb` 的第一个参数（上游叫 `sml_or_teecfg`）是**签名载体**——一个从设备上 dump 下来的、原厂签名且未修改过的合法镜像。它的作用不是"签名"你的新镜像，而是**提供一个被 SPL/FDL1 认可的原厂签名结构和 cert**，让 pre-verification 认为这不是伪造文件。

> 原理（kasnria001 POC）：Unisoc 在 SPL/FDL1 阶段**不校验镜像头**，校验逻辑**只用 cert header 里的 payload offset / payload size** 定位并检查 payload，并不把 payload 内容与签名做强绑定。`bsp_sign_fxxker` 输出 = 载体头部 + 修改后镜像 + 载体签名段，并把 cert 的 offset 平移，从而让修改后的镜像"借用"原厂签名结构。

### 选择标准

| 场景 | 签名载体（参数 1） | 说明 |
|---|---|---|
| patch **trustos**（TOS，AVB 检测所在） | sml **或** teecfg 都行 | 上游原话 `dis_avb_ex sml_or_teecfg tos`，两者等价 |
| patch **teecfg** | sml | teecfg 本身是 BSP 校验对象，载体须用 sml |
| patch **uboot**（`for_uboot` 版） | sml / teecfg | `bsp_sign_fxxker_for_uboot sml_teecfg uboot savefile` |

优先级建议（都有时按此顺序试）：

1. `sml_a` / `sml`（Secure Monitor Loader，EL3 监控器，加载最早、最通用的载体，kasnria001 的 POC 也是用它）
2. `teecfg_a` / `teecfg`（TEE 配置镜像，某些设备没有独立 sml 分区时用它）

### 怎么判断你手上这个文件能不能当载体

```bash
# 1. 从设备 dump 分区（或用已有备份），找到原厂未修改的 sml/teecfg
# 2. 检查结构是否合法：
file_off=$(printf '\x30' | od -An -tu4 -N4) # 或用 python:
python3 - <<'EOF'
import struct
for p in ['sml_a.bin', 'teecfg_a.bin']:
    d = open(p, 'rb').read(0x40)
    if len(d) < 0x34:
        print(p, 'too small'); continue
    magic, mimg = struct.unpack_from('<II', d, 0x00)
    print(p, 'magic=%08x mImgSize=%#x ->' % (magic, mimg),
          'OK 可用作载体' if magic == 0x42544844 and mimg else '无效')
EOF
```

必要条件：
- **magic = `0x42544844`（"BTHD" LE）**，`mImgSize`（偏移 0x30）非零
- **从设备 dump、未做任何修改**（原厂签名段 / cert 必须原样）
- 文件尾部能解析出 `sprdsignedimageheader`（cert_size/cert_offset 非零，`chsize` 能算出正确大小）
- 必须是设备**存在且被 SPL 校验链认可**的分区镜像；没有对应分区或版本不匹配则换另一个试

> ⚠️ 载体只负责"通过结构检查"；如果你的目的是禁用 AVB（`dis_avb`），修改目标是 **trustos**、签名载体任选 sml/teecfg；如果还要改 uboot，用 `uboot` 子命令（含 `patch_code`）。

---

## 验证

`verify.sh` 使用合成 DHTB 测试镜像（含两个以上可识别的 AArch64 函数块），对比原版 C 工具（`gen_tos-noavb.c` / `bsp_sign_fxxker.c` 直接 gcc 编译）与 Python/C++ 的输出字节：

```
gen_tos: py == ref OK / cpp == ref OK   (detected mov at 0x218/0x254/0x290, patch at 0x290)
fxxker:  py == ref OK / cpp == ref OK   (chsize 截断 0x3a0)
```

## 与上游的差异（有意的）

- 上游 `gen_tos-noavb.c` 会**就地截断覆盖输入文件**；本实现默认不改动输入，输出到新文件。
- `chsize_update_sha256` 的 SHA256 重算：Python 用 `hashlib.sha256`（等效）。
- C++ 中 `loadfile` 的 extra 填充语义以上游为准做了近似（零填充 vs 未初始化堆数据），对 16 对齐的真实镜像无影响。
