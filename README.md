# BNS

一个轻量的 DNS 转发器：

- UDP/TCP 53 监听，转发到上游 DNS（普通 UDP/TCP）
- 缓存：按响应 TTL 缓存（带 `min_ttl/max_ttl/negative_ttl`）
- 自定义解析：A / AAAA / CNAME 规则（精确/后缀/通配符）
- 查询日志：写入 SQLite，并提供 WebUI 查看与管理规则
- 日志保留：按 `retention_days` 定期清理

## 配置

复制 `config.example.yaml` 为 `config.yaml` 并按需修改：

```bash
cp config.example.yaml config.yaml
```

## 容器运行

```bash
docker compose up -d --build
```

- DNS：`udp/tcp :53`
- 管理界面：`http://127.0.0.1:8080/`

> 如果 `admin.token` 设置了值，WebUI/API 需要填写 Token（请求头为 `Authorization: Bearer <token>`）。

