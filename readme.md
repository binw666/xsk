# 简介
翻译自 [libxdp](https://github.com/xdp-project/xdp-tools/tree/f5501b1d9fa923858cdf7500d332e9295452984b) 并受 [xdp](https://github.com/asavie/xdp) 启发，开发一个纯 go 的 xsk 库。

# 警告

目前 xsk 还极不完善，请勿用于生产环境！！！

# 注意

- 内核版本 <= 5.3 的系统中，getsocketopt 没有 flag 字段，需要进一步处理，这里暂不支持 <= 5.3 的内核（相关函数 xskGetMmapOffsets）

# TODO

- [ ] xskSetupXdpProg 函数的实现（目前遇到问题：使用 ebpf 库加载 xdp 程序时，BTF 信息不完整，暂未找到解决方法）

# 依赖
```c
apt install libbpf-dev
# 如果是 24.04 或者 23.04 以上，则可以用以下命令
apt install libxdp-dev
# 否则，编译安装
git clone https://github.com/xdp-project/xdp-tools.git
cd xdp-tools
./configure
make
make install

```


TODO: C代码更改，支持锁，一边内核态可锁定