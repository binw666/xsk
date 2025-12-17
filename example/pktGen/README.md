# pktGen

基于 `github.com/binw666/xsk` 的 AF_XDP 发包工具。

## 特性

- YAML 支持 **多 flow / 多协议混发**（UDP/TCP/ICMPv4），每个 flow 可自定义各项参数（MAC/IP/TTL/端口/ICMP type-code）。
- 支持在 payload 中可选写入发送时间戳（默认写入 **16B 时间戳头**，运行时仅更新其中 8B 的 `sendNs` 字段，避免全包重建）。
- 支持限速：全局 pps（默认）或按队列 pps。

## 使用

构建：

`go build -o pktGen .`

运行（legacy 单 flow 配置仍可用，如 `udp.yaml`/`icmp.yaml`）：

`sudo ./pktGen -i ens1f1 -q 8 -c udp.yaml -r 100000`

混发示例：

`sudo ./pktGen -i ens1f1 -q 8 -c mixed.yaml -r 200000`

不限制发包速率：

`sudo ./pktGen -i ens1f1 -q 8 -c mixed.yaml -r -1`

## 配置（新 schema）

- `templates_per_flow`: 预生成模板数量（用于覆盖随机字段，降低运行时开销）。
- `payload`: 默认 payload 行为（flow 内可覆盖）
  - `random`: 是否随机填充 payload
  - `timestamp`: 可为 `true/false` 或 map
    - `enable`: 开关
    - `offset`: 写入到传输层 payload 的偏移（字节）
    - `magic`: 4 字节 magic（默认 `XSKT`）
- `flows`: flow 列表
  - `name`, `weight`, `total_size`, `ethernet`, `ip`, `transport`

时间戳头格式（payload 偏移处）：

- `magic[4] + version[2] + flags[2] + sendNs[8] (little endian, CLOCK_MONOTONIC 纳秒)`
