# AIS2API - Google AI Studio 转 OpenAI API 代理

AIS2API 是一个强大的代理服务器，它通过模拟浏览器操作，将 Google AI Studio 的 Web 界面转化为标准的 OpenAI API 格式。这使得你可以在任何支持 OpenAI 接口的客户端（如 SillyTavern 酒馆、NextChat 等）中，免费、无限制地使用 Google 的 Gemini 系列模型。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue)

## ✨ 主要特性

- 🚀 **OpenAI 接口兼容**: 完美适配 `v1/chat/completions` 和 `v1/models` 接口，支持流式 (Stream) 和非流式响应。
- 🔄 **多账号自动轮询**: 支持挂载无限个 Google 账号。系统会根据设定的请求次数或失败阈值自动切换账号，突破单账号的频率限制 (Rate Limit)。
- 🌊 **真·流式传输 (Real Stream)**: 独创的浏览器内部流式转发技术，实现与原生 API 无异的实时打字机效果，告别等待。
- 🧠 **思维链 (Thinking) 支持**: 完美适配 Gemini 2.0 Flash Thinking 等模型的思考过程输出 (`reasoning_content` / `<think>` 标签)，支持强制开启思考模式。
- 🖼️ **多模态支持**: 支持发送图片进行视觉识别 (Vision)。
- 📊 **Web 控制台**: 内置美观的 WebUI，可实时监控服务状态、查看调用日志、统计图表、手动切换账号及调整配置。
- 🛡️ **高可用设计**: 具备自动重试、死锁检测、浏览器崩溃自动恢复机制。

## 📦 部署指南

推荐使用 Docker 进行部署，这是最简单且最稳定的方式。

### 1. 准备工作

首先，克隆或下载本项目到你的服务器/本地电脑。

### 2. 获取认证信息 (Cookie)

为了让服务器能代表你访问 Google AI Studio，你需要先提取登录后的 Cookie 信息。本项目提供了一个便捷的脚本来完成此操作。

**前提**: 本地需要安装 Node.js 环境。

1.  安装依赖:

    ```bash
    npm install
    ```

2.  运行获取脚本:

    ```bash
    node save-auth.js
    ```

3.  脚本会自动启动一个浏览器窗口。

    - 在弹出的浏览器中，登录你的 Google 账号。
    - 登录成功进入 AI Studio 界面后，回到终端按 **回车** 键。
    - 脚本会自动提取认证信息，并保存为 `auth/auth-1.json`。

4.  **多账号**: 如果你有多个账号，重复运行上述步骤即可。脚本会自动命名为 `auth-2.json`, `auth-3.json` 等。

### 3. 配置环境变量

复制或修改 `app.env` 文件，设置你的服务配置：

```ini
# app.env

# 设置连接本服务的密码 (API Key)，支持设置多个，用逗号分隔
API_KEYS=sk-123456,sk-password

# (可选) 单个账号使用多少次后自动切换到下一个账号
SWITCH_ON_USES=50

# (可选) 账号连续失败多少次后自动切换
FAILURE_THRESHOLD=3

# (可选) 流式模式: real (真流式，推荐) 或 fake (伪流式，一次性返回)
STREAMING_MODE=real

# (可选) 遇到这些错误码时立即切换账号
IMMEDIATE_SWITCH_STATUS_CODES=429,503
```

### 4. 启动服务

根据你的环境选择一种部署方式。

#### 方式 A: 使用 Docker Compose (VPS/本地服务器推荐)

这是最简单的管理方式，支持自动重启和日志管理。

```bash
docker-compose up -d
```

服务启动后，默认监听 **7862** 端口 (可在 `docker-compose.yml` 中修改)。

#### 方式 B: 全云端/PaaS 平台部署 (Zeabur / Claw / Render 等)

如果你使用 Zeabur、Claw Cloud 或其他容器托管平台，请参考以下配置：

1.  **创建服务**: 选择“部署 Docker 镜像”。
2.  **镜像名称 (Image)**: `ghcr.io/in-dor/ais2api:latest`
    - _(注: 原教程中的 `ellinalopez/cloud-studio:latest` 为旧版，请务必使用上述新版镜像)_
3.  **端口设置 (Port)**:
    - 容器端口: `7860` (必须是这个)
    - 公网端口: 开启 Public Access
4.  **资源建议 (Resources)**:
    - CPU: 0.5 Core 以上
    - Memory: 1 GB 以上
5.  **环境变量 (Environment Variables)**:
    - 在平台的“设置”或“环境变量”页面添加以下内容：
    - `API_KEYS`: (必填) 设置你的访问密码，如 `sk-123456`。
    - `AUTH_JSON_1`: (必填) 打开你生成的 `auth/auth-1.json` 文件，复制**全部内容**填入。
    - `AUTH_JSON_2`: (可选) 如果有多账号，依此类推填入第二个文件的内容。
    - `SWITCH_ON_USES`: (可选) 建议设为 `50`。
    - `STREAMING_MODE`: (可选) 建议设为 `real`。

> 📚 详细的 **全云端部署图文教程** (涵盖 Claw/Zeabur/VPS) 请参考：
> [**全云端 Build 轮询反代部署指南**](https://gcn02iwpisfi.feishu.cn/wiki/UMDzwFu0ki3AEfkQ3A7c7bHvnIL) > _(注：教程中的镜像名请替换为本项目最新的 `ghcr.io/in-dor/ais2api:latest`)_

#### 方式 C: 使用 Shell 部署脚本 (Linux)

```bash
chmod +x deploy.sh
./deploy.sh
```

#### 方式 D: 直接运行 (Node.js 源码部署)

如果不使用 Docker，请确保本地已安装 Firefox 浏览器依赖。

```bash
npm start
```

---

## 🛠️ 使用说明

### API 调用

服务启动后，你可以像使用 OpenAI API 一样使用它。

- **Base URL**: `http://<你的服务器IP>:7862/v1` (注意端口取决于你的 docker 映射)
- **API Key**: 你在 `app.env` 中设置的 `API_KEYS` (例如 `sk-123456`)
- **Model**: 支持 Google AI Studio 上的任何模型 ID，例如:
  - `gemini-2.0-flash-thinking-exp-1219`
  - `gemini-2.0-flash-exp`
  - `gemini-1.5-pro-latest`

#### 示例 (curl)

```bash
curl http://localhost:7862/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-123456" \
  -d '{
    "model": "gemini-2.0-flash-exp",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'
```

### Google Gemini 原生 API 支持

除了 OpenAI 格式，本项目也**原生支持** Google Gemini API 格式。这意味着你可以直接使用官方文档中的 endpoint 和请求体，只需将域名替换为你的服务地址。

**Base URL**: `http://<你的服务器IP>:7862` (不带 `/v1`)

#### 示例 (Gemini 原生格式)

```bash
curl "http://localhost:7862/v1beta/models/gemini-2.0-flash-exp:generateContent?key=sk-123456" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts": [{"text": "Explain how AI works"}]
    }]
  }'
```

> 注意：在使用原生格式时，API Key 可以通过 URL 参数 `?key=...` 传递，也可以通过 Header `x-goog-api-key` 传递。

### Web 控制台

访问 `http://<你的服务器IP>:7862` (默认端口) 即可进入 Web 控制台。

- **登录**: 使用 `app.env` 中配置的 `API_KEYS` 登录。
- **功能**:
  - **服务状态**: 查看浏览器连接状态、当前使用的账号。
  - **控制面板**: 手动切换账号、切换流式模式、开启/关闭强制思考。
  - **日志**: 查看实时的请求和错误日志。
  - **统计**: 查看每日调用次数图表。

## 🧩 高级配置

### 配置文件 (config.json)

除了环境变量，你也可以在根目录创建 `config.json` 进行配置 (优先级高于环境变量)：

```json
{
  "httpPort": 7860,
  "streamingMode": "real",
  "switchOnUses": 50,
  "apiKeys": ["你的密码"]
}
```

## ⚠️ 注意事项

1.  **账号安全**: 请妥善保管生成的 `auth/*.json` 文件，它们包含了你的 Google 登录凭证。不要分享给他人。
2.  **网络环境**: 确保你的服务器可以访问 `aistudio.google.com`。如果在国内服务器部署，可能需要配置 `HTTP_PROXY` 环境变量。
3.  **浏览器资源**: 每个账号对应一个浏览器上下文。虽然做了优化，但大量账号可能会占用较多内存。建议 `SWITCH_ON_USES` 设置在 50-100 左右，避免长时间运行导致的浏览器卡顿。

## 📝 License

MIT License
