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
