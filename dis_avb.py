#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dis_avb patch 逻辑的 Python 复刻（Unisoc/SPRD pre-verification 绕过）

对应上游源码：
  1. action_spd_dump_it/gen_tos-noavb.c        -> gen_tos_noavb()   (trustos 的 mov patch 算法)
  2. action_spd_dump_it/chsize.c                -> chsize()          (DHTB 镜像截断到真实 footprint)
  3. unisoc_chipram_signcheck_exploit/
     Patch-Pre-Verification/bsp_sign_fxxker.c   -> bsp_sign_fxxker() (用已签名 sml/teecfg 包装修改后的 tos)
     Patch-Pre-Verification/bsp_sign_fxxker_for_uboot.c -> patch_code_uboot() (可选的 uboot 分支 patch)

dis_avb 命令本质（README: "dis_avb_ex sml_or_teecfg tos" -> 保存 tos-noavb-bsp-bypassed）：
  1) 对 trustos 运行 gen_tos 算法：扫描 AArch64 指令序列，定位 AVB 检查函数中的
     "mov x0, sp"(0x910003E0) 指令，patch 成 "mov w0,#0"(0x52800000)，使检查函数返回 0(成功)
  2) 对 sml/teecfg 运行 bsp_sign_fxxker：截断原始签名文件到真实大小，把修改后的
     trustos payload 塞进原始头部与签名尾部(footer+certs)之间，并同步增大 mImgSize、
     payload_offset、cert_offset —— 保持 bootrom 侧 pre-verification 仍能通过签名校验
"""

import struct
import sys

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
MAGIC_DHTB = 0x42544844          # "BTHD" (小端读)
MAGIC_DHSP = 0x50534844          # "DHSP" (postrom)
SYS_IMG_HEADER_SIZE = 0x200      # sys_img_header 大小
SIGNED_IMG_HDR_SIZE = 0x60       # sprdsignedimageheader 大小

RET_INSN             = 0xD65F03C0  # ret
LDP_X29_X30_MASK     = 0xA8007BFD  # ldp x29,x30,[sp],#imm   (epilogue)
STP_X29_X30_MASK     = 0xA9007BFD  # stp x29,x30,[sp,#-imm]!  (prologue)
MOV_W0_0             = 0x52800000  # mov w0,#0                (patch 写入值)
MOV_X0_SP_LOW16      = 0x03E0      # add x0,sp,#0 的低 16 位

# sprdsignedimageheader 字段偏移(u64 LE)，相对 footer 起始
CERT_SIZE_OFF        = 0x20
CERT_OFF_OFF         = 0x28
PRIV_SIZE_OFF        = 0x30
PRIV_OFF_OFF         = 0x38
DBGDEV_SIZE_OFF      = 0x50
DBGDEV_OFF_OFF       = 0x58


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


def u16(buf, off):
    return struct.unpack_from('<H', buf, off)[0]


def u64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0]


def loadfile(path, extra=0):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if extra:
        data.extend(b'\x00' * (extra - (len(data) % extra)) if len(data) % extra else b'')
    return data


# ---------------------------------------------------------------------------
# dhtb_data_size：计算 DHTB 数据块的真实大小（含 SIMGHDR footer + certs）
# 对应 gen_tos-noavb.c / chsize_update_sha256.c 中的同名函数
# ---------------------------------------------------------------------------
def dhtb_data_size(buf, img_size, max_rel, base=0):
    raw_end = 0x200 + img_size
    if raw_end + SIGNED_IMG_HDR_SIZE > max_rel:
        return raw_end
    fb = base + raw_end  # footer 地址
    max_end = raw_end + SIGNED_IMG_HDR_SIZE
    # 同时满足：ss/so 非零，且 so+ss > max_end，且 so+ss <= max_rel
    for s_off, o_off in ((CERT_SIZE_OFF, CERT_OFF_OFF),
                         (PRIV_SIZE_OFF, PRIV_OFF_OFF),
                         (DBGDEV_SIZE_OFF, DBGDEV_OFF_OFF)):
        ss = u64(buf, fb + s_off)
        so = u64(buf, fb + o_off)
        if ss and so and (so + ss) > max_end and (so + ss) <= max_rel:
            max_end = so + ss
    return max_end


# ---------------------------------------------------------------------------
# chsize：把 DHTB 文件原地截断到真实大小
# 对应 chsize.c（bsp_sign_fxxker.c 内嵌的旧版 chsize，32 位字段读取）
# ---------------------------------------------------------------------------
def chsize_old(buf):
    """返回截断后大小；与原 C 版行为一致。"""
    size = len(buf)
    if u32(buf, 0) != MAGIC_DHTB:
        raise SystemExit('The file is not sprd trusted firmware')
    img_size = u32(buf, 0x30)
    if not img_size:
        raise SystemExit('broken sprd trusted firmware')
    if img_size + 0x260 >= size:
        print('0x%x' % size)
        return size
    # footer 位于 0x200 + mImgSize
    fb = img_size + 0x200
    # 依次检查 cert_dbg_developer / priv / cert 三组 (offset, size)，取第一组两者非零的
    for s_off, o_off in ((0x50, 0x58), (0x30, 0x38), (0x20, 0x28)):
        s_val = u32(buf, fb + s_off)
        o_val = u32(buf, fb + o_off)
        if s_val and o_val:
            return o_val + s_val
    return img_size + 0x200


def chsize_update_sha256(buf):
    """
    对应 chsize_update_sha256.c：截断到真实大小并重算 mPayloadHash(SHA256 of payload)。
    （在 patch 修改 payload 后，签名哈希需要重算，bootrom 侧 pre-verification 才能通过）
    """
    import hashlib
    size = len(buf)
    if u32(buf, 0) != MAGIC_DHTB:
        raise SystemExit('The file is not sprd trusted firmware')
    header = buf  # sys_img_header
    sizewith_postrom = 0
    postrom_off = u32(header, 0xC0)      # mPostromOffset
    if postrom_off and postrom_off + 0x200 < size:
        pbase = postrom_off
        pmagic = u32(buf, pbase)
        pimg_size = u32(buf, pbase + 0x30)
        if (pmagic in (MAGIC_DHTB, MAGIC_DHSP)) and pimg_size and \
                (postrom_off + 0x200 + pimg_size <= size):
            sizewith_postrom = postrom_off + dhtb_data_size(buf, pimg_size,
                                                            size - postrom_off,
                                                            base=postrom_off)
        # 重算 postrom payload 的 sha256
        h = hashlib.sha256(buf[pbase + 0x200: pbase + 0x200 + pimg_size]).digest()
        buf[pbase + 8: pbase + 8 + 32] = h     # mPayloadHash
    img_size = u32(buf, 0x30)
    if not img_size:
        raise SystemExit('broken sprd trusted firmware')
    size = dhtb_data_size(buf, img_size, size)
    size = max(size, sizewith_postrom)
    print('0x%x' % size)
    # 重算主 payload 的 sha256
    h = hashlib.sha256(buf[0x200: 0x200 + img_size]).digest()
    buf[8: 8 + 32] = h
    return size


# ---------------------------------------------------------------------------
# gen_tos_noavb：对 trustos 的 mov patch（对应 gen_tos-noavb.c）
# 输入 DHTB 镜像字节，返回 (截断后字节, patch 位置列表, 选择的 patch 偏移)
# ---------------------------------------------------------------------------
def gen_tos_noavb(data, force_single=False):
    if u32(data, 0) != MAGIC_DHTB:
        raise SystemExit('The file is not sprd trusted firmware')
    img_size = u32(data, 0x30)
    if not img_size:
        raise SystemExit('broken sprd trusted firmware')
    size = dhtb_data_size(data, img_size, len(data))
    data = data[:size]

    pmov = [0, 0, 0]
    mov_count = 0
    last_start_pos = 0
    start_pos = 0

    i = 0x200
    while i < size:
        current = u32(data, i)
        if current == RET_INSN or (current & 0xFF00FFFF) == LDP_X29_X30_MASK:
            last_start_pos = 0
            start_pos = 0
        elif (current & 0xFF00FFFF) == STP_X29_X30_MASK:
            if start_pos:
                last_start_pos = start_pos
            start_pos = i
        elif start_pos:
            ldp_count = 0
            for m in range(0, 20, 4):
                o = i + m + 3
                if o < size and data[o] == 0xA9:
                    ldp_count += 1
                else:
                    break
            if ldp_count == 5:
                ret_flag = 0
                for m in range(24, 32, 4):
                    if i + m + 4 <= size and u32(data, i + m) == RET_INSN:
                        ret_flag += 1
                if ret_flag:
                    if u16(data, i - 4) == MOV_X0_SP_LOW16 and data[i - 7] == 0x3:
                        count1 = 0
                        count2 = 0
                        for m in range(start_pos, i, 4):
                            v = u32(data, m)
                            if v >> 16 == 0x9400:      # BL
                                count1 += 1
                            elif v >> 16 == 0xb400:    # CBZ
                                count2 += 1
                        if count1 and count2 and count1 + count2 > 2:
                            print('detected mov at 0x%x' % (i - 4))
                            if mov_count < 3:
                                pmov[mov_count] = i - 4
                                mov_count += 1
                            else:
                                pmov[0] = pmov[1]
                                pmov[1] = pmov[2]
                                pmov[2] = i - 4
        i += 4

    if mov_count < 2:
        if force_single and mov_count == 1:
            print('warning: only 1 candidate detected, forcing patch')
            print('patch mov at 0x%x' % pmov[0])
            struct.pack_into('<I', data, pmov[0], MOV_W0_0)
            return data, pmov[:1], pmov[0]
        print('dis_avb: skip saving!!!')
        return data, pmov[:mov_count], None
    if mov_count > 2:
        mov_count = 1 if (pmov[2] - 2 * pmov[1] + pmov[0] > 0) else 2
    else:
        mov_count -= 1
    patch_off = pmov[mov_count]
    print('patch mov at 0x%x' % patch_off)
    struct.pack_into('<I', data, patch_off, MOV_W0_0)
    return data, pmov[:max(len(pmov) and mov_count + 1, 0)], patch_off


# ---------------------------------------------------------------------------
# bsp_sign_fxxker：用已签名文件(原文件) 包装修改后的镜像
# 对应 bsp_sign_fxxker.c
#   signed:    原始已签名文件路径 (sml/teecfg)，会被 chsize 截断
#   modified:  修改后的镜像 (trustos)，若带 DHTB 头则剥离头与 payload
# 返回输出字节
# ---------------------------------------------------------------------------
def _loadfile_extra(data, extra):
    """模拟 C 版 loadfile 的 extra 语义：*num 向上取整到 extra 倍数，缓冲区尾部补零。"""
    n = len(data)
    if not extra:
        return data, n
    padded = bytearray(data)
    pad = (extra - (n % extra)) % extra
    padded.extend(b'\x00' * pad)
    return padded, n + pad


def bsp_sign_fxxker(signed, modified, multi_header=False):
    """对应 bsp_sign_fxxker.c (MULTI_HEADER=0) / bsp_sign_fxxker_for_uboot.c (MULTI_HEADER=1)。

    signed:   原始已签名文件 (sml/teecfg) —— 先 chsize 原地截断
    modified: 修改后的镜像 (trustos/uboot)
    输出: 原头部(mImgSize 增大) + 修改后的 payload [+ 修改镜像的 footer/cert 段] + 原签名镜像的
          payload 之后剩余部分(footer+certs)。同步增大 payload_offset / cert_offset。
    """
    signed = bytearray(signed[:chsize_old(signed)])
    signed_img_size = len(signed)
    orig_signed_img_size = u32(signed, 0x30)
    if u32(signed, 0) != MAGIC_DHTB or not orig_signed_img_size:
        raise SystemExit('The file is not sprd trusted firmware')

    signed_img_size -= SYS_IMG_HEADER_SIZE

    # 带 extra=16 的 loadfile（for_uboot 版本传入 16，普通版传入 0）
    modified, _ = _loadfile_extra(modified, 16) if multi_header else (modified, len(modified))
    modified_img_size = len(modified)
    modified_headers_size = 0
    orig_modified_img_size = u32(modified, 0x30)
    if u32(modified, 0) == MAGIC_DHTB and orig_modified_img_size:
        if multi_header:
            # 修改后镜像去掉头部+payload 后的剩余段（footer/certs），随输出一并带过去
            modified_headers_size = modified_img_size - orig_modified_img_size - SYS_IMG_HEADER_SIZE
        modified_img_size = orig_modified_img_size
        modified = modified[SYS_IMG_HEADER_SIZE:]

    out = bytearray(SYS_IMG_HEADER_SIZE + modified_img_size + modified_headers_size + signed_img_size)

    # 原头部：mImgSize 增大
    sys_img_hdr = bytearray(signed[:SYS_IMG_HEADER_SIZE])
    new_mimg_size = orig_signed_img_size + modified_img_size + modified_headers_size
    struct.pack_into('<I', sys_img_hdr, 0x30, new_mimg_size)
    if multi_header:
        struct.pack_into('<I', sys_img_hdr, 0x38, orig_modified_img_size)  # mImgSizeOrig

    # 原 footer 位于 signed 的 payload 之后；记录偏移增量
    img_hdr_off = SYS_IMG_HEADER_SIZE + orig_signed_img_size
    delta = modified_img_size + modified_headers_size
    if img_hdr_off + SIGNED_IMG_HDR_SIZE <= len(signed):
        payload_offset = u64(signed, img_hdr_off + 0x18) + delta
        cert_offset = u64(signed, img_hdr_off + 0x28) + delta
    else:
        payload_offset = cert_offset = 0

    out[:SYS_IMG_HEADER_SIZE] = sys_img_hdr
    p = SYS_IMG_HEADER_SIZE
    out[p:p + modified_img_size] = modified[:modified_img_size]
    p += modified_img_size
    if multi_header and modified_headers_size:
        # C 版这里复制的是 modified 缓冲区 payload 之后的 "headers" 段
        out[p:p + modified_headers_size] = modified[modified_img_size:modified_img_size + modified_headers_size]
        p += modified_headers_size
    # 原签名文件头部之后的剩余部分（原 payload + footer + certs）
    out[p:] = signed[SYS_IMG_HEADER_SIZE:SYS_IMG_HEADER_SIZE + signed_img_size]

    # 回填输出中 footer 的偏移字段（输出 footer 位置 = 0x200 + new_mimg_size）
    if payload_offset or cert_offset:
        out_ftr = SYS_IMG_HEADER_SIZE + new_mimg_size
        if out_ftr + SIGNED_IMG_HDR_SIZE <= len(out):
            struct.pack_into('<Q', out, out_ftr + 0x18, payload_offset)
            struct.pack_into('<Q', out, out_ftr + 0x28, cert_offset)
    return bytes(out)


# ---------------------------------------------------------------------------
# patch_code_uboot：uboot 的 BSP 检查 patch（对应 bsp_sign_fxxker_for_uboot.c）
# 修改内存中的 uboot 镜像：把 ldr w?, [x?, #0xC] 的偏移改为 0xE，并把 bne 改为 b
# ---------------------------------------------------------------------------
def decode_bcond_offset(inst):
    imm19 = (inst >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 |= ~0x7FFFF
    return imm19 << 2


def patch_code_uboot(mem):
    size = len(mem)
    for i in range(0x200, size, 4):
        current = u32(mem, i)
        if current == RET_INSN or (current & 0xFF00FFFF) == LDP_X29_X30_MASK:
            pos_cmp = pos_ldr = pos_add = pos_bne = 0
        elif (current & 0xFFFF0000) == 0xB9400000:   # ldr w?, [x?, #imm]
            if ((current >> 10) & 0xFFF) == 0xC:     # #0xC -> 待改
                pos_ldr = i
                pos_cmp = pos_add = pos_bne = 0
                reg_ldr = current & 0x1F
                start = max(pos_ldr - 0x80, 0x200)
                end = min(pos_ldr + 0x80, size)
                for m in range(start, end, 4):
                    cur = u32(mem, m)
                    if (cur & 0xFFFF0000) == 0x71000000:   # cmp w?, #imm
                        if ((cur >> 10) & 0xFFF) == 1:
                            pos_cmp = m
                    elif (cur & 0xFFFF0000) == 0x91080000: # add x?, x?, #imm
                        reg_add = (cur >> 5) & 0x1F
                        if reg_ldr == reg_add:
                            pos_add = m
                    elif pos_add and (cur & 0xFF000000) == 0x54000000:  # b.cond
                        pos_bne = m
                    if pos_cmp and pos_bne:
                        print('cmp 0x%x, ldr 0x%x, add 0x%x, bne 0x%x' % (pos_cmp, pos_ldr, pos_add, pos_bne))
                        cur = u32(mem, pos_ldr)
                        cur &= ~(0xFFF << 10)
                        cur |= (0xE << 10)
                        struct.pack_into('<I', mem, pos_ldr, cur)
                        cur = u32(mem, pos_bne)
                        off = decode_bcond_offset(cur)
                        struct.pack_into('<I', mem, pos_bne, 0x14000000 + (off // 4))
                        break
    return mem


# ---------------------------------------------------------------------------
# 命令行
# ---------------------------------------------------------------------------
def main():
    import os
    import tempfile

    if len(sys.argv) < 2:
        print(__doc__)
        print('用法:')
        print('  dis_avb.py gen_tos [--force-single] <tos.bin> [out.bin]  # gen_tos 算法 -> tos-noavb.bin')
        print('  dis_avb.py chsize <file.bin>                  # 截断 DHTB 到真实大小（原地）')
        print('  dis_avb.py fxxker <signed.bin> <mod.bin> <out> # bsp_sign_fxxker 包装')
        print('  dis_avb.py dis_avb [选项] <sml_or_teecfg> <tos.bin> [out] # 完整 dis_avb 流程')
        print('')
        print('  --force-single  只找到 1 个候选点时仍强制 patch（默认要求 >=2 个）')
        print('  --pad-to <size> 输出用 0x00 补齐到指定大小（支持 0x 前缀）')
        print('  --pad-to-input  输出补齐到原始 tos.bin 的大小（分区全量镜像用）')
        return 1

    cmd = sys.argv[1]

    if cmd == 'gen_tos':
        a = 2
        force_single = False
        if len(sys.argv) > a and sys.argv[a] == '--force-single':
            force_single = True
            a += 1
        if len(sys.argv) <= a:
            return 1
        data = loadfile(sys.argv[a])
        out, pmov, patch_off = gen_tos_noavb(data, force_single)
        if patch_off is None:
            return 1
        out_path = sys.argv[a + 1] if len(sys.argv) > a + 1 else 'tos-noavb.bin'
        with open(out_path, 'wb') as f:
            f.write(out)
        print('saved to %s' % out_path)
    elif cmd == 'chsize':
        data = loadfile(sys.argv[2])
        size = chsize_old(data)
        with open(sys.argv[2], 'wb') as f:
            f.write(data[:size])
    elif cmd == 'fxxker':
        signed = loadfile(sys.argv[2])
        modified = loadfile(sys.argv[3])
        out = bsp_sign_fxxker(signed, modified)
        with open(sys.argv[4], 'wb') as f:
            f.write(out)
        print('saved to %s' % sys.argv[4])
    elif cmd == 'dis_avb':
        # dis_avb_ex sml_or_teecfg tos -> tos-noavb-bsp-bypassed
        a = 2
        force_single = False
        pad_to_input = False
        pad_to = 0
        while a < len(sys.argv):
            opt = sys.argv[a]
            if opt == '--force-single':
                force_single = True
                a += 1
            elif opt == '--pad-to-input':
                pad_to_input = True
                a += 1
            elif opt == '--pad-to' and a + 1 < len(sys.argv):
                pad_to = int(sys.argv[a + 1], 0)
                if pad_to <= 0:
                    print('invalid --pad-to value: %s' % sys.argv[a + 1])
                    return 1
                a += 2
            else:
                break
        if len(sys.argv) <= a + 1:
            return 1
        sml = loadfile(sys.argv[a])
        tos = loadfile(sys.argv[a + 1])
        tos_file_size = len(tos)
        tos_patched, _, patch_off = gen_tos_noavb(tos, force_single)
        if patch_off is None:
            print('gen_tos failed: no patch target found')
            return 1
        out = bsp_sign_fxxker(sml, tos_patched)
        if pad_to_input:
            pad_to = tos_file_size
        if pad_to:
            if pad_to < len(out):
                print('--pad-to 0x%x is smaller than output 0x%x' % (pad_to, len(out)))
                return 1
            out = out + b'\x00' * (pad_to - len(out))
        out_path = sys.argv[a + 2] if len(sys.argv) > a + 2 else 'tos-noavb-bsp-bypassed'
        with open(out_path, 'wb') as f:
            f.write(out)
        print('saved to %s (patched_off=0x%x, size=0x%x)' % (out_path, patch_off, len(out)))
    else:
        print('unknown command: %s' % cmd)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())