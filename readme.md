# 简介
翻译自 [libxdp](https://github.com/xdp-project/xdp-tools/tree/f5501b1d9fa923858cdf7500d332e9295452984b) 并受 [xdp](https://github.com/asavie/xdp) 启发，开发一个纯 go 的 xsk 库。

# 警告

目前 xsk 还极不完善，请勿用于生产环境！！！

# 注意

- 内核版本 <= 5.3 的系统中，getsocketopt 没有 flag 字段，需要进一步处理，这里暂不支持 <= 5.3 的内核（相关函数 xskGetMmapOffsets）
- 内核版本 <= 5.3 的系统中，`bpf_redirect_map` 的函数与之后的定义冲突，未实现检测方法，这里暂不支持 <= 5.3 的内核（相关函数 XskSetupXdpProg）

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
# 需要挂载bpf文件系统
mount -t bpf none /sys/fs/bpf
```

# 示例

参考 `example` 文件夹中的 `pktGen` 和 `pktRecv`

# 已知问题

- rx 通道 bug：在填充 FillRing 后，从 RxRing 回收的 Desc 的 addr 会变成 addr + 256 , 将 addr + 256 填充后，回收则不会变化，可能是内存对齐的问题？或者程序bug？
