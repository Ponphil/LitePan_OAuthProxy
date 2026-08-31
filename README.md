# LitePan OAuth 认证代理

这是 LitePan 的认证代理服务，用来代替 LitePan 获取和刷新各网盘授权。你可以自行部署，数据和请求都由自己的服务器处理。

## 支持的平台

115 网盘、百度网盘、123 云盘、OneDrive、光鸭云盘。

## 快速部署

需要 Python 3.10 或更高版本。

```bash
git clone <本仓库地址>
cd oauth_proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py
```

默认监听 `5288` 端口。正式使用时，建议用 Nginx 或 Caddy 配置 HTTPS，并在 `.env` 中填写：

```env
EXTERNAL_URL=https://oauth.example.com
INTERNAL_PORT=5288
STATS_PASSWORD=请设置统计页密码
STATS_SECRET=请设置随机密钥
```

然后填写 `.env.example` 中对应网盘的 OAuth 参数。生产环境可使用：

```bash
uvicorn main:app --host 0.0.0.0 --port 5288 --workers 1
```

OAuth 会话暂存在进程内，建议单进程运行，不要直接暴露 5288 端口。外网访问必须使用 HTTPS。

## OAuth 回调地址

在各平台的应用设置中，将回调地址填写为：

```text
https://oauth.example.com/callback-popup
```

将域名替换成自己的域名，并与 `EXTERNAL_URL` 完全一致。

## LitePan 中使用

进入 LitePan「系统设置 → 其他设置」，找到“OAuth 代理服务地址”，填写：

```text
https://oauth.example.com
```

保存后，LitePan 的网盘授权会通过这台代理完成。

## 统计页

- 页面：`/stats`
- 数据接口：`/api/stats`
- 重置统计：`POST /api/stats/reset`

统计数据仅统计被调用次数，不统计任何网盘认证信息。

## 本地开发

```bash
pip install -r requirements.txt
python main.py
```

启动后可访问 `http://127.0.0.1:5288/docs` 查看 API 文档。
