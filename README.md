# Port Guard

`port-guard` 是一个面向 Alpine、Debian、Ubuntu 的单端口来源白名单脚本。它只接管你指定的协议和端口，例如 `tcp/443`，允许固定 IP、IP 列表文件、远程 URL IP 列表、域名解析结果访问，其余来源会被 `DROP` 或 `REJECT`。

核心设计：

- 每个端口使用独立配置，例如 `/etc/port-guard/rules/tcp_443.conf`。
- 每个端口使用独立 `ipset` 和专用 `iptables` chain，例如 `PG_TCP_443`。
- 只在 `INPUT` 链挂一条指定端口跳转规则，不重置防火墙，不改其它端口，也不改 ufw 配置。
- URL 和域名支持定时更新，失败时自动使用上次成功缓存，避免网络抖动把白名单清空。
- 支持 IPv4/IPv6；目标系统缺少 `ip6tables` 时会提示 IPv6 未受保护。

## 快速使用

### 一键下载安装

使用 `curl`：

```sh
curl -fsSL -o port-guard.sh https://raw.githubusercontent.com/allenmien/port-guard/main/port-guard.sh && chmod +x port-guard.sh && sudo ./port-guard.sh
```

或使用 `wget`：

```sh
wget -O port-guard.sh https://raw.githubusercontent.com/allenmien/port-guard/main/port-guard.sh && chmod +x port-guard.sh && sudo ./port-guard.sh
```

如果想下载后直接安装为系统命令：

```sh
curl -fsSL -o port-guard.sh https://raw.githubusercontent.com/allenmien/port-guard/main/port-guard.sh && chmod +x port-guard.sh && sudo ./port-guard.sh install
```

安装完成后即可使用：

```sh
sudo port-guard add --port 443 --proto tcp \
  --ip 1.2.3.4 \
  --ips "5.6.7.0/24,8.8.8.8" \
  --file /root/allow.txt \
  --url https://example.com/allow.txt \
  --domain example.com \
  --interval 30
```

如果已经 clone 了仓库，也可以在项目目录里运行：

```sh
sudo ./port-guard.sh
```

## 命令

```sh
# 查看规则
sudo port-guard status

# 立即更新 URL/域名并应用全部规则
sudo port-guard update all

# 只更新到期规则，通常由 cron 每分钟调用
sudo port-guard update due

# 重新应用现有缓存和规则
sudo port-guard apply all

# 删除某个端口的所有托管规则
sudo port-guard delete --proto tcp --port 443
sudo port-guard delete --proto both --port 443

# 重置所有 port-guard 管理的规则和配置
sudo port-guard reset

# 卸载脚本、定时任务、开机恢复服务，并删除所有托管规则
sudo port-guard uninstall
```

## IP 列表格式

本地文件和远程 URL 都可以写成一行一个，也可以混用空格、逗号、分号：

```txt
1.2.3.4
5.6.7.0/24
2001:db8::/32
# 注释会被忽略
```

## 定时更新

`install` 会尽量安装：

- 开机恢复：systemd、OpenRC local.d，或 crontab `@reboot`。
- 定时更新：优先 systemd timer，否则 `/etc/cron.d/port-guard`、root crontab 或 Alpine `/etc/crontabs/root`。

定时任务每分钟运行一次 `port-guard update due --quiet`，但每条端口规则会按自己的 `--interval` 判断是否需要更新，所以 `--interval 30` 就是约 30 分钟更新一次。

## 兼容性和依赖

脚本目标 shell 是 `/bin/sh`，兼容 Debian/Ubuntu 的 `dash` 和 Alpine 的 BusyBox `ash`。依赖：

- `iptables`
- `ip6tables`，用于 IPv6
- `ipset`
- `curl`、`wget` 或 `fetch` 之一，用于下载 URL IP 列表
- `getent`、`dig`、`host` 或 `nslookup` 之一，用于解析域名

`install` 会尝试用 `apk` 或 `apt-get` 安装 `iptables ipset curl`。如果系统环境比较精简，手动安装上述依赖即可。

## 注意

这个工具会让指定端口进入严格白名单模式。例如配置 `tcp/443` 后，不在白名单里的来源访问 `tcp/443` 会被拒绝；其它端口不受影响。
