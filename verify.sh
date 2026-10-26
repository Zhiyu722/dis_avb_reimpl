#!/bin/bash
# 对照验证: 原版C工具 vs Python复刻 vs C++复刻
set -e
cd /root/dis_avb_reimpl

echo "=== 生成测试镜像 ==="
python3 gen_test_images.py

echo
echo "=== [1] gen_tos (trustos patch) 对照 ==="
# 原版 C
rm -f tests/ref_tos-noavb.bin tests/ref_*.log
( cd ref && rm -f temp tos-noavb.bin && ./gen_tos_ref ../tests/gen_tos_test.bin > ../tests/ref_gen_tos.log && mv tos-noavb.bin ../tests/ref_tos-noavb.bin )
echo "--- 原版C 输出:"
cat tests/ref_gen_tos.log

# Python 复刻
rm -f tests/py_tos-noavb.bin
python3 dis_avb.py gen_tos tests/gen_tos_test.bin tests/py_tos-noavb.bin 2>&1 | sed 's/^/[py] /'

# C++ 复刻
rm -f tests/cpp_tos-noavb.bin
./dis_avb gen_tos tests/gen_tos_test.bin tests/cpp_tos-noavb.bin 2>&1 | sed 's/^/[cpp] /'

echo "--- 字节对比:"
cmp tests/ref_tos-noavb.bin tests/py_tos-noavb.bin && echo "py  == ref OK" || echo "py  != ref FAIL"
cmp tests/ref_tos-noavb.bin tests/cpp_tos-noavb.bin && echo "cpp == ref OK" || echo "cpp != ref FAIL"

echo
echo "=== [2] fxxker (sml/teecfg 签名包装) 对照 ==="
# 原版 C (会原地截断 signed_test.bin, 先复制)
rm -f tests/ref_signed.bin tests/ref_out.bin
cp tests/signed_test.bin tests/ref_signed.bin
( cd ref && rm -f temp && cp ../tests/ref_signed.bin ./signed_in.bin && ./fxxker_ref signed_in.bin ../tests/modified_test.bin ../tests/ref_out.bin > ../tests/ref_fxxker.log )
echo "--- 原版C 输出:"
cat tests/ref_fxxker.log
echo "--- 截断后 signed (原版 chsize 生效):"
ls -la tests/ref_signed.bin tests/ref_out.bin

# Python 复刻
rm -f tests/py_out.bin tests/py_signed.bin
cp tests/signed_test.bin tests/py_signed.bin
python3 dis_avb.py fxxker tests/py_signed.bin tests/modified_test.bin tests/py_out.bin 2>&1 | sed 's/^/[py] /'

# C++ 复刻
rm -f tests/cpp_out.bin
./dis_avb fxxker tests/signed_test.bin tests/modified_test.bin tests/cpp_out.bin 2>&1 | sed 's/^/[cpp] /'

echo "--- 字节对比:"
cmp tests/ref_out.bin tests/py_out.bin && echo "py  == ref OK" || echo "py  != ref FAIL"
cmp tests/ref_out.bin tests/cpp_out.bin && echo "cpp == ref OK" || echo "cpp != ref FAIL"

echo
echo "=== [3] dis_avb 完整流程 (Python/C++ 内部一致性) ==="
rm -f tests/py_full.bin tests/cpp_full.bin
python3 dis_avb.py dis_avb tests/signed_test.bin tests/gen_tos_test.bin tests/py_full.bin 2>&1 | sed 's/^/[py] /'
./dis_avb dis_avb tests/signed_test.bin tests/gen_tos_test.bin tests/cpp_full.bin 2>&1 | sed 's/^/[cpp] /'
cmp tests/py_full.bin tests/cpp_full.bin && echo "py == cpp OK" || echo "py != cpp FAIL"

echo
echo "=== 全部完成 ==="
