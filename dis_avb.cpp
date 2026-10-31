// dis_avb.cpp - Unisoc/SPRD "dis_avb" patch 逻辑的 C++ 复刻
//
// 对应上游源码（算法 1:1 移植，保持行为一致）:
//   1. action_spd_dump_it/gen_tos-noavb.c                    -> gen_tos_noavb()
//   2. action_spd_dump_it/chsize.c                            -> chsize_old()
//   3. unisoc_chipram_signcheck_exploit/Patch-Pre-Verification/
//      bsp_sign_fxxker.c         (MULTI_HEADER=0)             -> bsp_sign_fxxker()
//      bsp_sign_fxxker_for_uboot.c (MULTI_HEADER=1)           -> bsp_sign_fxxker_uboot()
//
// 编译: g++ -O2 -std=c++17 -o dis_avb dis_avb.cpp
// 用法:
//   dis_avb gen_tos <tos.bin> [out.bin]          # gen_tos 算法 -> tos-noavb
//   dis_avb chsize <file.bin>                     # 原地截断 DHTB
//   dis_avb fxxker <signed.bin> <mod.bin> <out>   # bsp_sign_fxxker 包装
//   dis_avb dis_avb <sml_or_teecfg> <tos.bin> [out]  # 完整 dis_avb 流程
//   dis_avb uboot <sml_or_teecfg> <uboot.bin> <out>   # for_uboot 版本(带 patch_code)

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------
static constexpr u32 MAGIC_DHTB      = 0x42544844; // "BTHD" (LE)
static constexpr u32 MAGIC_DHSP      = 0x50534844; // "DHSP" (postrom)
static constexpr u32 SYS_IMG_HDR_SZ  = 0x200;      // sys_img_header
static constexpr u32 SIGNED_HDR_SZ   = 0x60;       // sprdsignedimageheader

static constexpr u32 RET_INSN        = 0xD65F03C0; // ret
static constexpr u32 LDP_X29_X30     = 0xA8007BFD; // ldp x29,x30,[sp],#imm (epilogue)
static constexpr u32 STP_X29_X30     = 0xA9007BFD; // stp x29,x30,[sp,#-imm]! (prologue)
static constexpr u32 MOV_W0_0        = 0x52800000; // mov w0,#0

// sprdsignedimageheader 字段偏移(相对 footer 起始, u64 LE)
static constexpr u32 CERT_SIZE_OFF   = 0x20;
static constexpr u32 CERT_OFF_OFF    = 0x28;
static constexpr u32 PRIV_SIZE_OFF   = 0x30;
static constexpr u32 PRIV_OFF_OFF    = 0x38;
static constexpr u32 DBGDEV_SIZE_OFF = 0x50;
static constexpr u32 DBGDEV_OFF_OFF  = 0x58;

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
static u32 rd32(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }
static u16 rd16(const u8 *p) { u16 v; memcpy(&v, p, 2); return v; }
static u64 rd64(const u8 *p) { u64 v; memcpy(&v, p, 8); return v; }
static void wr32(u8 *p, u32 v) { memcpy(p, &v, 4); }
static void wr64(u8 *p, u64 v) { memcpy(p, &v, 8); }

static std::vector<u8> loadfile(const std::string &fn, size_t *num = nullptr, size_t extra = 0)
{
    std::vector<u8> buf;
    FILE *fi = fopen(fn.c_str(), "rb");
    if (fi) {
        fseek(fi, 0, SEEK_END);
        long n = ftell(fi);
        fseek(fi, 0, SEEK_SET);
        if (n > 0) {
            buf.resize((size_t)n + extra);
            size_t j = fread(buf.data(), 1, (size_t)n, fi);
            if (num) {
                if (extra)
                    *num = ((j + extra - 1) / extra) * extra; // 向上取整到 extra 倍数
                else
                    *num = j;
            }
        }
        fclose(fi);
    }
    return buf;
}

static void savefile(const std::string &fn, const u8 *data, size_t sz)
{
    FILE *f = fopen(fn.c_str(), "wb");
    if (!f) { fprintf(stderr, "cannot create %s\n", fn.c_str()); exit(1); }
    size_t w = fwrite(data, 1, sz, f);
    if (w != sz) { fprintf(stderr, "write failed %s\n", fn.c_str()); exit(1); }
    fclose(f);
}

[[noreturn]] static void err_exit(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    exit(1);
}

// ---------------------------------------------------------------------------
// dhtb_data_size：DHTB 数据块真实 footprint（含 SIMGHDR footer + certs）
// 对应 gen_tos-noavb.c / chsize_update_sha256.c
// ---------------------------------------------------------------------------
static size_t dhtb_data_size(const u8 *base, u32 mImgSize, size_t max_rel)
{
    size_t raw_end = 0x200 + mImgSize;
    if (raw_end + SIGNED_HDR_SZ > max_rel)
        return raw_end;
    const u8 *pf = base + raw_end; // SIMGHDR-style footer
    size_t max_end = raw_end + SIGNED_HDR_SZ;
    auto check_seg = [&](u64 ss, u64 so) {
        if (ss && so && so + ss > max_end && so + ss <= max_rel)
            max_end = (size_t)(so + ss);
    };
    check_seg(rd64(pf + CERT_SIZE_OFF), rd64(pf + CERT_OFF_OFF));
    check_seg(rd64(pf + PRIV_SIZE_OFF), rd64(pf + PRIV_OFF_OFF));
    check_seg(rd64(pf + DBGDEV_SIZE_OFF), rd64(pf + DBGDEV_OFF_OFF));
    return max_end;
}

// ---------------------------------------------------------------------------
// chsize_old：旧版截断逻辑（bsp_sign_fxxker.c 内嵌版本, 32 位字段读取）
// 返回截断后大小
// ---------------------------------------------------------------------------
static size_t chsize_old(const u8 *mem, size_t size)
{
    if (rd32(mem) != MAGIC_DHTB)
        err_exit("The file is not sprd trusted firmware\n");
    u32 mImgSize = rd32(mem + 0x30);
    if (!mImgSize)
        err_exit("broken sprd trusted firmware\n");
    if (mImgSize + 0x260 >= size) {
        printf("0x%zx\n", size);
        return size;
    }
    const u8 *fb = mem + mImgSize + 0x200; // footer
    // 依次检查 cert_dbg_developer / priv / cert: (size, offset) 均非零则取 offset+size
    static const int pairs[3][2] = {
        { 0x50, 0x58 }, { 0x30, 0x38 }, { 0x20, 0x28 }
    };
    for (auto &pr : pairs) {
        u32 s_val = rd32(fb + pr[0]);
        u32 o_val = rd32(fb + pr[1]);
        if (s_val && o_val) {
            size_t sz = (size_t)o_val + s_val;
            printf("0x%zx\n", sz);
            return sz;
        }
    }
    size_t sz = mImgSize + 0x200;
    printf("0x%zx\n", sz);
    return sz;
}

// ---------------------------------------------------------------------------
// gen_tos_noavb：trustos 的 mov patch（对应 gen_tos-noavb.c）
// 输入完整 DHTB 镜像字节; 返回 (patch 后字节, patch 偏移或 -1)
// ---------------------------------------------------------------------------
static std::vector<u8> gen_tos_noavb(const std::vector<u8> &in, ssize_t *patch_off_out,
                                     bool force_single = false)
{
    if (in.size() < 4 || rd32(in.data()) != MAGIC_DHTB)
        err_exit("The file is not sprd trusted firmware\n");
    u32 mImgSize = rd32(in.data() + 0x30);
    if (!mImgSize)
        err_exit("broken sprd trusted firmware\n");
    size_t size = dhtb_data_size(in.data(), mImgSize, in.size());
    std::vector<u8> mem(in.begin(), in.begin() + size);

    size_t pmov[3] = { 0, 0, 0 };
    int mov_count = 0;
    size_t last_start_pos = 0, start_pos = 0;

    for (size_t i = 0x200; i + 4 <= size; i += 4) {
        u32 current = rd32(mem.data() + i);
        if (current == RET_INSN || (current & 0xFF00FFFF) == LDP_X29_X30) {
            last_start_pos = 0;
            start_pos = 0;
        } else if ((current & 0xFF00FFFF) == STP_X29_X30) {
            if (start_pos)
                last_start_pos = start_pos;
            start_pos = i;
        } else if (start_pos) {
            int ldp_count = 0;
            for (int m = 0; m < 20; m += 4) {
                if (i + m + 4 <= size && mem[i + m + 3] == 0xA9)
                    ldp_count++;
                else
                    break;
            }
            if (ldp_count == 5) {
                int ret_flag = 0;
                for (int m = 24; m < 32; m += 4) {
                    if (i + m + 4 <= size && rd32(mem.data() + i + m) == RET_INSN)
                        ret_flag++;
                }
                if (ret_flag) {
                    if (i >= 8 && rd16(mem.data() + i - 4) == 0x3E0 && mem[i - 7] == 0x3) {
                        int count1 = 0, count2 = 0;
                        for (size_t m = start_pos; m < i; m += 4) {
                            u32 v = rd32(mem.data() + m);
                            if ((v >> 16) == 0x9400)      // BL
                                count1++;
                            else if ((v >> 16) == 0xb400) // CBZ
                                count2++;
                        }
                        if (count1 && count2 && count1 + count2 > 2) {
                            printf("detected mov at 0x%zx\n", i - 4);
                            if (mov_count < 3) {
                                pmov[mov_count] = i - 4;
                                mov_count++;
                            } else {
                                pmov[0] = pmov[1];
                                pmov[1] = pmov[2];
                                pmov[2] = i - 4;
                            }
                        }
                    }
                }
            }
        }
    }

    if (mov_count < 2) {
        if (force_single && mov_count == 1) {
            printf("warning: only 1 candidate detected, forcing patch\n");
            printf("patch mov at 0x%zx\n", pmov[0]);
            wr32(mem.data() + pmov[0], MOV_W0_0);
            if (patch_off_out) *patch_off_out = (ssize_t)pmov[0];
            return mem;
        }
        printf("dis_avb: skip saving!!!\n");
        if (patch_off_out) *patch_off_out = -1;
        return mem;
    }
    if (mov_count > 2)
        mov_count = (pmov[2] - 2 * pmov[1] + pmov[0] > 0) ? 1 : 2;
    else
        mov_count--;
    printf("patch mov at 0x%zx\n", pmov[mov_count]);
    wr32(mem.data() + pmov[mov_count], MOV_W0_0);
    if (patch_off_out) *patch_off_out = (ssize_t)pmov[mov_count];
    return mem;
}

// ---------------------------------------------------------------------------
// bsp_sign_fxxker：已签名文件包装修改后镜像
// multi_header=false -> bsp_sign_fxxker.c (MULTI_HEADER=0)
// multi_header=true  -> bsp_sign_fxxker_for_uboot.c (MULTI_HEADER=1, 另含 patch_code)
// ---------------------------------------------------------------------------
static std::vector<u8> bsp_sign_fxxker(const std::vector<u8> &signed_in,
                                       std::vector<u8> modified,
                                       bool multi_header)
{
    std::vector<u8> signed_img = signed_in;
    size_t signed_img_size = chsize_old(signed_img.data(), signed_img.size());
    signed_img.resize(signed_img_size);

    size_t orig_signed_img_size = rd32(signed_img.data() + 0x30);
    if (rd32(signed_img.data()) != MAGIC_DHTB || !orig_signed_img_size)
        err_exit("The file is not sprd trusted firmware\n");

    signed_img_size -= SYS_IMG_HDR_SZ;

    // 上游 for_uboot 版对 modified 用 loadfile(argv[2], &modified_img_size, 16)：
    // modified_img_size 向上取整到 16 的倍数（缓冲区多出的字节未初始化）。
    // 普通版用 extra=0。为忠实复刻，multi_header 时把 modified 视为已按 16 对齐。
    size_t modified_img_size = modified.size();
    if (multi_header) {
        modified_img_size = (modified_img_size + 15) / 16 * 16; // 向上取整到 16 倍数
        if (modified_img_size > modified.size()) {
            // loadfile 的 extra 语义：缓冲区大小 = n + extra，*num 向上取整；
            // 多出的 1..15 字节视为零填充（原 C 中为未初始化堆数据，此处以 0 近似）
            modified.resize(modified_img_size, 0);
        }
    }

    size_t modified_headers_size = 0;
    u32 orig_modified_img_size = (modified.size() >= 4) ? rd32(modified.data() + 0x30) : 0;
    if (modified.size() >= 4 && rd32(modified.data()) == MAGIC_DHTB && orig_modified_img_size) {
        if (multi_header) {
            if (modified.size() >= SYS_IMG_HDR_SZ + orig_modified_img_size)
                modified_headers_size = modified.size() - orig_modified_img_size - SYS_IMG_HDR_SZ;
        }
        modified_img_size = orig_modified_img_size;
        modified.erase(modified.begin(), modified.begin() + SYS_IMG_HDR_SZ);
    }

    size_t out_sz = SYS_IMG_HDR_SZ + modified_img_size + modified_headers_size + signed_img_size;
    std::vector<u8> out(out_sz, 0);

    // 原头部拷贝 + mImgSize 增大
    u8 *sys_img_hdr = out.data();
    memcpy(sys_img_hdr, signed_img.data(), SYS_IMG_HDR_SZ);
    u32 new_mimg_size = (u32)(orig_signed_img_size + modified_img_size + modified_headers_size);
    wr32(sys_img_hdr + 0x30, new_mimg_size);
    if (multi_header)
        wr32(sys_img_hdr + 0x38, orig_modified_img_size); // mImgSizeOrig

    // 原 footer: payload_offset / cert_offset 增大
    size_t img_hdr_off = SYS_IMG_HDR_SZ + orig_signed_img_size;
    size_t delta = modified_img_size + modified_headers_size;
    u64 payload_offset = 0, cert_offset = 0;
    if (img_hdr_off + SIGNED_HDR_SZ <= signed_img.size()) {
        payload_offset = rd64(signed_img.data() + img_hdr_off + 0x18) + delta;
        cert_offset = rd64(signed_img.data() + img_hdr_off + 0x28) + delta;
    }

    // 组装: header | modified payload | modified headers | signed 剩余
    u8 *p = out.data() + SYS_IMG_HDR_SZ;
    memcpy(p, modified.data(), modified_img_size);
    p += modified_img_size;
    if (multi_header && modified_headers_size) {
        // C 版此处复制的是原 modified 缓冲区 payload 之后的 segment
        // （原缓冲区在去掉头部前的大小 = SYS_IMG_HDR_SZ + mImgSize + headers）
        memcpy(p, modified.data() + modified_img_size, modified_headers_size);
        p += modified_headers_size;
    }
    memcpy(p, signed_img.data() + SYS_IMG_HDR_SZ, signed_img_size);

    // 回填输出中 footer 的偏移字段
    if (payload_offset || cert_offset) {
        size_t out_ftr = SYS_IMG_HDR_SZ + new_mimg_size;
        if (out_ftr + SIGNED_HDR_SZ <= out.size()) {
            wr64(out.data() + out_ftr + 0x18, payload_offset);
            wr64(out.data() + out_ftr + 0x28, cert_offset);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// patch_code：uboot 的 BSP 检查分支 patch（对应 bsp_sign_fxxker_for_uboot.c）
// 修改 ldr w?,[x?,#0xC] -> #0xE，并把对应 bne 改为无条件 b
// ---------------------------------------------------------------------------
static int32_t decode_bcond_offset(u32 inst)
{
    int32_t imm19 = (inst >> 5) & 0x7FFFF;
    if (imm19 & (1 << 18))
        imm19 |= ~0x7FFFF;
    return imm19 << 2;
}

static void patch_code(std::vector<u8> &mem)
{
    size_t size = mem.size();
    size_t pos_cmp = 0, pos_ldr = 0, pos_add = 0, pos_bne = 0;
    for (size_t i = 0x200; i + 4 <= size; i += 4) {
        u32 current = rd32(mem.data() + i);
        if (current == RET_INSN || (current & 0xFF00FFFF) == LDP_X29_X30) {
            pos_cmp = pos_ldr = pos_add = pos_bne = 0;
        } else if ((current & 0xFFFF0000) == 0xB9400000) { // ldr w?, [x?, #imm]
            if (((current >> 10) & 0xFFF) == 0xC) {        // #0xC
                pos_ldr = i;
                pos_cmp = pos_add = pos_bne = 0;
                u32 reg_ldr = current & 0x1F;
                size_t lo = (pos_ldr >= 0x80) ? pos_ldr - 0x80 : 0x200;
                size_t hi = (pos_ldr + 0x80 + 4 <= size) ? pos_ldr + 0x80 : (size > 4 ? size - 4 : 0);
                for (size_t m = lo; m < hi && m + 4 <= size; m += 4) {
                    u32 cur = rd32(mem.data() + m);
                    if ((cur & 0xFFFF0000) == 0x71000000) { // cmp w?, #imm
                        if (((cur >> 10) & 0xFFF) == 1)
                            pos_cmp = m;
                    } else if ((cur & 0xFFFF0000) == 0x91080000) { // add x?, x?, #imm
                        u32 reg_add = (cur >> 5) & 0x1F;
                        if (reg_ldr == reg_add)
                            pos_add = m;
                    } else if (pos_add && (cur & 0xFF000000) == 0x54000000) { // b.cond
                        pos_bne = m;
                    }
                    if (pos_cmp && pos_bne) {
                        printf("cmp 0x%zx, ldr 0x%zx, add 0x%zx, bne 0x%zx\n",
                               pos_cmp, pos_ldr, pos_add, pos_bne);
                        u32 c = rd32(mem.data() + pos_ldr);
                        c &= ~(0xFFFu << 10);
                        c |= (0xEu << 10);
                        wr32(mem.data() + pos_ldr, c);
                        c = rd32(mem.data() + pos_bne);
                        int32_t off = decode_bcond_offset(c);
                        wr32(mem.data() + pos_bne, (u32)(0x14000000 + (uint32_t)off / 4));
                        goto done;
                    }
                }
            }
        }
    }
done:
    return;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  dis_avb gen_tos [--force-single] <tos.bin> [out.bin]            # gen_tos 算法 -> tos-noavb\n"
            "  dis_avb chsize <file.bin>                                       # 原地截断 DHTB(需要写 temp)\n"
            "  dis_avb fxxker <signed.bin> <mod.bin> <out>                     # bsp_sign_fxxker 包装\n"
            "  dis_avb dis_avb [--force-single] <sml_or_teecfg> <tos.bin> [out] # 完整 dis_avb 流程\n"
            "  dis_avb uboot <sml_or_teecfg> <uboot.bin> <out>                 # for_uboot 版本(含 patch_code)\n"
            "\n"
            "  --force-single  只找到 1 个候选点时仍强制 patch(默认要求 >=2 个)\n");
        return 1;
    }
    std::string cmd = argv[1];

    if (cmd == "gen_tos") {
        int a = 2;
        bool force_single = false;
        if (a < argc && std::string(argv[a]) == "--force-single") {
            force_single = true;
            a++;
        }
        if (a >= argc) return 1;
        std::vector<u8> in = loadfile(argv[a]);
        ssize_t off = -1;
        std::vector<u8> out = gen_tos_noavb(in, &off, force_single);
        if (off < 0) return 1;
        std::string o = (a + 1 < argc) ? argv[a + 1] : "tos-noavb.bin";
        savefile(o, out.data(), out.size());
        printf("saved to %s\n", o.c_str());
    } else if (cmd == "chsize") {
        if (argc < 3) return 1;
        std::vector<u8> mem = loadfile(argv[2]);
        size_t sz = chsize_old(mem.data(), mem.size());
        savefile("temp", mem.data(), sz);
        remove(argv[2]);
        rename("temp", argv[2]);
        printf("resized to 0x%zx\n", sz);
    } else if (cmd == "fxxker") {
        if (argc < 5) return 1;
        std::vector<u8> signed_img = loadfile(argv[2]);
        std::vector<u8> modified = loadfile(argv[3]);
        std::vector<u8> out = bsp_sign_fxxker(signed_img, modified, false);
        savefile(argv[4], out.data(), out.size());
        printf("saved to %s (0x%zx bytes)\n", argv[4], out.size());
    } else if (cmd == "dis_avb") {
        int a = 2;
        bool force_single = false;
        if (a < argc && std::string(argv[a]) == "--force-single") {
            force_single = true;
            a++;
        }
        if (a + 1 >= argc) return 1;
        std::vector<u8> sml = loadfile(argv[a]);
        std::vector<u8> tos = loadfile(argv[a + 1]);
        ssize_t off = -1;
        std::vector<u8> tos_patched = gen_tos_noavb(tos, &off, force_single);
        if (off < 0) return 1;
        std::vector<u8> out = bsp_sign_fxxker(sml, tos_patched, false);
        std::string o = (a + 2 < argc) ? argv[a + 2] : "tos-noavb-bsp-bypassed";
        savefile(o, out.data(), out.size());
        printf("saved to %s (patched_off=0x%zx, size=0x%zx)\n", o.c_str(), off, out.size());
    } else if (cmd == "uboot") {
        if (argc < 5) return 1;
        std::vector<u8> sml = loadfile(argv[2]);
        std::vector<u8> uboot = loadfile(argv[3]);
        patch_code(uboot);
        std::vector<u8> out = bsp_sign_fxxker(sml, uboot, true);
        savefile(argv[4], out.data(), out.size());
        printf("saved to %s (0x%zx bytes)\n", argv[4], out.size());
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd.c_str());
        return 1;
    }
    return 0;
}