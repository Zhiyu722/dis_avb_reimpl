#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成合成 DHTB 测试镜像，用于验证三套实现（原版C / Python / C++）输出一致。"""
import struct

def build_header(mimg_size):
    """sys_img_header (0x200 字节): magic BTHD @0x00, mImgSize @0x30"""
    h = bytearray(0x200)
    struct.pack_into('<I', h, 0x00, 0x42544844)  # "BTHD"
    struct.pack_into('<I', h, 0x04, 1)           # version
    struct.pack_into('<I', h, 0x30, mimg_size)
    return h

def insn(v):
    return struct.pack('<I', v)

# ============================================================
# 1. gen_tos 测试镜像: 3 个"函数块"，每个块:
#    stp x29,x30  -> 若干 BL/CBZ -> mov x29,sp -> mov x0,sp
#    -> 5x A9 高字节指令 -> nop -> ret
#    检测点 i: u16@i-4==0x3E0, byte@i-7==0x3
# ============================================================
def build_gen_tos_img():
    body = bytearray()
    def block(base_bl, base_cbz, off):
        b = bytearray()
        b += insn(0xA9007BFD)                 # stp x29,x30,[sp,#-imm]!  (start_pos)
        b += insn(0x94000000 | base_bl)       # BL  (count1)
        b += insn(0x94000000 | base_bl)       # BL  (count1)
        b += insn(0xB4000000 | base_cbz)      # CBZ (count2)
        b += insn(0x94000000 | base_bl)       # BL  (count1)
        b += insn(0x910003FD)                 # mov x29,sp  (bytes FD 03 00 91)
        b += insn(0x910003E0)                 # mov x0,sp   (bytes E0 03 00 91)
        # 检测点 i: 5 个高字节==0xA9 的指令（非 x29/x30 对，避免掩码匹配）
        for _ in range(5):
            b += insn(0xA90053F3)             # stp x19,x20 形式 (byte3==0xA9)
        b += insn(0xD503201F)                 # nop (第6个字, 不参与)
        b += insn(0xD65F03C0)                 # ret @ i+24 (ret_flag)
        b += insn(0xD65F03C0)                 # ret @ i+28
        return b

    body += block(0x100, 0x000, 0)            # F1: 检测点 i=0x220, pmov[0]=0x21C
    body += block(0x200, 0x000, 1)            # F2: 检测点 i=0x258, pmov[1]=0x254
    body += block(0x300, 0x000, 2)            # F3: 检测点 i=0x298, pmov[2]=0x294

    img = build_header(len(body))
    img += body
    return bytes(img)

# ============================================================
# 2. fxxker 测试: signed 镜像 (带 footer+cert+多余尾部) + modified 镜像
# ============================================================
def build_signed_img():
    mimg = 0x100
    img = bytearray(build_header(mimg))
    img += bytes([0xAA]) * mimg                    # payload @0x200..0x300
    # footer @0x300 (sprdsignedimageheader, 0x60)
    ftr = bytearray(0x60)
    ftr[0:8] = b'SIGNHDR!'
    struct.pack_into('<Q', ftr, 0x10, mimg)        # payload_size
    struct.pack_into('<Q', ftr, 0x18, 0x200)       # payload_offset
    struct.pack_into('<Q', ftr, 0x20, 0x40)        # cert_size
    struct.pack_into('<Q', ftr, 0x28, 0x360)       # cert_offset
    img += ftr
    img += bytes([0xBB]) * 0x40                    # cert @0x360..0x3A0
    img += bytes([0xCC]) * 0x60                    # 多余尾部 @0x3A0..0x400 (chsize 截掉)
    return bytes(img)

def build_modified_img():
    mimg = 0x80
    img = bytearray(build_header(mimg))
    img += bytes([0x11]) * mimg
    return bytes(img)

if __name__ == '__main__':
    import os
    os.makedirs('/root/dis_avb_reimpl/tests', exist_ok=True)
    with open('/root/dis_avb_reimpl/tests/gen_tos_test.bin', 'wb') as f:
        f.write(build_gen_tos_img())
    with open('/root/dis_avb_reimpl/tests/signed_test.bin', 'wb') as f:
        f.write(build_signed_img())
    with open('/root/dis_avb_reimpl/tests/modified_test.bin', 'wb') as f:
        f.write(build_modified_img())
    print('test images written:')
    for n in ('gen_tos_test.bin', 'signed_test.bin', 'modified_test.bin'):
        print('  %s  %d bytes' % (n, os.path.getsize('/root/dis_avb_reimpl/tests/' + n)))