# 📦 UDP 广播包转发器 / UDP Broadcast Packet Forwarder

## 🧩 功能说明 | Description

这是一个使用原始套接字编写的 C 程序，用于从一个网口抓取 UDP 广播包，并修改其源 MAC 地址为另一个网口的 MAC 地址，然后将该包通过另一个网口重新发送。

This is a C program using raw sockets to capture UDP broadcast packets from one network interface, replace their source MAC address with the MAC address of another interface, and re-send them out via the target interface.

## 🚀 特性 | Features

- 抓取并识别以太网广播包（目的 MAC 为 `ff:ff:ff:ff:ff:ff`）  
- 判断是否是 IPv4 UDP 广播包（目标 IP 形如 `192.168.X.255`）  
- 自动读取发送接口的 MAC 地址，并替换原包的源 MAC  
- 自动跳过 IP 分片包（即 `More Fragment` 或 Offset ≠ 0）

## 🛠️ 编译 | Build

```bash
gcc -o ipc-replay ipc-replay.c
```

## 🧪 使用方法 | Usage
```bash
sudo ./ipc-replay <接收接口> <发送接口>
```
例如：
```bash
sudo ./ipc-replay phy0-sta0 br-lan
```
>⚠️ 必须以 root 权限运行，否则无法打开原始套接字
>⚠️ Must be run as root due to raw socket usage
