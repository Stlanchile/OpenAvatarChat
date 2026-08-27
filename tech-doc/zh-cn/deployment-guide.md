# OpenAvatarChat 部署指南

**语言：** 简体中文 · [English](../deployment-guide.md)

## 1. 部署前必读

本指南聚焦 OpenAvatarChat 核心服务；Beta OpenClaw 路径不属于主要部署目标。

仓库中随附的部署文件可以作为开发脚手架，但不能直接作为安全的公网部署方案。
请特别注意：

- 不要将应用端口 `8282` 或 `8283` 直接暴露到公网；
- 不要使用其已检入凭据部署 `coturn-data/turnserver.conf`；
- 不要认为执行 `docker compose up` 后 TURN 就能直接使用；
- 除非实际加载有效证书/密钥对，否则不要声明 HTTPS；
- 修复重复的 YAML 键之前，不要使用 Qwen-Omni 预设；
- 不要将 API 密钥置于启用 Manager 的 YAML 文件中；
- 不要把 M8 录取通知书按钮或 `certificate-ocr` Compose profile 当作生产 OCR 已完成连线或资格验证的证据。

面向公网运行时，应在应用前部署带身份验证的 TLS 入口，并使用单独加固的 TURN 服务。
传统/默认模式没有内建身份验证。
启用证书模式后会增加按用途绑定的 OIDC 及会话/传输/Manager 准入，但仍没有通用限流；入口控制仍是必需项，而非可选优化。

对于显式证书配置门禁之外的启动失败，进程仍可能返回退出码 `0`。
部署验收必须检查明确的就绪状态和日志证据，不能只根据退出码判断成功。

## 2. 选择部署方式

| 部署方式 | 适用场景 | 优势 | 主要限制 |
|---|---|---|---|
| 原生 `uv` | 首次安装、开发、单台专用 GPU 主机 | 最容易诊断；仅安装目标预设所需依赖 | 必须控制主机系统库和 Python；依赖解析未纳入版本控制，也未锁定 |
| 独立 Docker | 修正镜像内容后的隔离式单机运行 | 内置 CUDA、Python 和系统依赖 | 宽泛的 `.dockerignore` 会移除处理程序 YAML；镜像包含全部处理程序且体积较大；以 root 用户运行；依赖版本浮动 |
| Docker Compose | 实验室中的应用与 coturn 编排 | 配置完成后可通过一条命令启动 | 随附的 TURN 配置不安全，密钥挂载也有误；应用不会自动向浏览器提供 TURN 配置 |
| `certificate-ocr` Compose profile | 隔离式资格验证/部署脚手架 | 无网络 CPU-only sidecar、私有 UDS、只读运行时 | 无法用于生产：缺少获批锁文件/模型/身份/资格验证，且生产 Seal 从不调用 OCR/提取服务 |
| 公网生产拓扑 | 远程用户访问 | 受信任 TLS、身份验证、速率限制和明确配置的 TURN | 需要额外入口、安全加固和问题修复；仓库未提供可直接投产的完整方案 |

推荐顺序：

1. 先在本机使用原生方式验证目标预设。
2. 记录其模型、GPU 内存、延迟和所需出口流量。
3. 针对该精确提交构建并验证不可变镜像。
4. 添加经身份验证的 TLS 入口。
5. 仅在客户端网络需要时添加并从外部测试 TURN。
6. 在提高 `chat_engine.concurrent_limit` 前，对预期会话数进行负载测试。

## 3. 部署目标与平台约束

仓库明确面向 Linux x86-64、Ubuntu 22.04、Python 3.11 和 NVIDIA CUDA 12.8 容器环境。
部分处理程序或许可以在其他平台上以原生方式运行，但现有部署产物没有覆盖这些平台。

源代码中的硬性约束：

- Python `>=3.11.7,<3.12`；
- PyTorch `2.8.0` CUDA 12.8 wheel 包；
- Git 子模块和 Git LFS；
- FFmpeg 以及音频/图形系统库；
- 文档中的预设和容器路径需要 NVIDIA GPU。

证书 OCR sidecar 是刻意隔离的 CPU 工作负载。
它不得初始化 CUDA，也不得使用主应用 GPU。
CPU 类别、精确 backend、线程数、模型、包锁、哈希和资源预算都是资格验证输入，不能从通用 CUDA 目标推导。

对于 CUDA 12.8 镜像，建议以不低于 `570.26` 的 Linux NVIDIA 驱动作为运维基线。
NVIDIA 文档将 `525.60.13` 列为 CUDA 12.x 次版本兼容机制的较低下限，但它并不是 CUDA 12.8.1 生产镜像最稳妥的选择。
参见[CUDA 12.8 发行说明](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-toolkit-release-notes/index.html)。

仓库没有规定最低 GPU 型号、显存、内存、磁盘容量或网络带宽。
这些指标必须针对目标预设实测，不能把历史文档中的 RTX 4090 延迟或显存数据当作容量保证。

## 4. 网络与浏览器访问方式

| 客户端位置 | 应用 TLS | TURN | 建议暴露方式 |
|---|---|---|---|
| 同一主机，通过 `localhost` 访问 | 开发阶段可使用 HTTP，因为浏览器把 `localhost` 视为潜在可信来源 | 通常不需要 | 尽量只绑定回环地址 |
| 受信任 LAN | 强烈建议受信任 HTTPS；浏览器必须信任证书 | 取决于 LAN/NAT 策略 | 受限防火墙/VPN；无直接公开监听器 |
| 公网 | 相机/麦克风必须使用受信任 HTTPS | 如需可靠覆盖受限 NAT，则必须提供 | 在 443 端口部署带身份验证的反向代理；使用独立 TURN 主机 |
| 嵌入 iframe | HTTPS 加 Permissions Policy 和 iframe `allow` 属性 | 依赖网络 | 明确 `camera`/`microphone` 策略 |

浏览器 `getUserMedia()` 只能在安全上下文中使用；
参见[MDN](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)和 [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/)。

## 5. 通用部署前检查

### 5.1 固定源代码版本

为便于复现审查结果和完成部署交接，请使用指定的发布提交，不要直接部署未固定的分支：

```bash
git clone https://github.com/HumanAIGC-Engineering/OpenAvatarChat.git
cd OpenAvatarChat
git checkout <approved-commit>
git lfs install
git submodule update --init --recursive
git submodule status --recursive
```

预期的子模块状态是：每个干净且已初始化的子模块前都有一个空格。
前导 `-` 表示未初始化；`+` 表示检出了不同的提交。
在固定版本的部署中，不要使用 `git submodule update --remote`。

本次审查对应的提交为：

```text
6db2b96176afc9f324d022e01f96b3cf3d811699
```

### 5.2 主机检查

```bash
nvidia-smi
git --version
git lfs version
ffmpeg -version
openssl version
df -h .
free -h
```

对于容器，还应检查：

```bash
docker version
docker compose version
docker run --rm --gpus all nvidia/cuda:12.8.1-base-ubuntu22.04 nvidia-smi
```

如果本地没有该镜像，最后一条命令会拉取镜像。
在受控/离线环境中，请改用已批准的本地镜像副本。

NVIDIA 当前的 Docker 运行时设置方式为：

```bash
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

参见[NVIDIA Container Toolkit 安装指南](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)。

### 5.3 出站访问清单

仅允许所选预设和模型来源所需的端点。
潜在出口访问包括：

- 安装期间访问 PyPI/uv 和 PyTorch CUDA 12.8 索引；
- 通过 GitHub 和 Git LFS 获取子模块；
- 通过 ModelScope、Hugging Face、`hf-mirror.com` 或阿里云 OSS 获取模型；
- 已配置的 OpenAI-compatible、DashScope/Bailian、Dify 或 Edge TTS 端点；
- DNS 和受信任的 CA/OCSP 服务；
- TURN（如果在外部托管）。

仓库不会把模型和依赖下载固定到不可变版本，也不会验证校验和。
对于离线或生产构建，应在内部镜像中保存已批准的产物，生成摘要清单，并在摘要不匹配时拒绝启动。

### 5.4 选择预设

| 需求 | 起始预设 | 额外准备 |
|---|---|---|
| 最简单的核心 RTC 路径 | `config/chat_with_openai_compatible_bailian_cosyvoice.yaml` | `DASHSCOPE_API_KEY`、LiteAvatar 权重和数字人资源 |
| 本地 TTS | `config/chat_with_openai_compatible.yaml` | 本地 CosyVoice 依赖项/模型；安装更重 |
| 无 TTS API 密钥 | `config/chat_with_openai_compatible_edge_tts.yaml` | Edge TTS 网络可达性；仍需 LLM 密钥 |
| 用户中断/双工对话 | `..._bailian_cosyvoice_duplex.yaml` | Smart Turn 指定的 ONNX 文件和语义 LLM 凭据 |
| MuseTalk | `..._musetalk.yaml` | MuseTalk 模型、源视频、相同的 RTC/数字人 FPS，以及容器中的 `PYTORCH_JIT=0` |
| FlashHead | `..._flashhead.yaml` | FlashHead + wav2vec 模型、`flash-attn` 构建、保守并发量 |
| LAM 客户端渲染 | `config/chat_with_lam.yaml` | LAM 模型和所选 LAM 资产 |
| Qwen-Omni | `config/chat_with_qwen_omni.yaml` | **在修复重复的 `connection_ttl` 前受阻** |

除非确实需要在同一开发环境中安装所有处理程序，否则不要一开始就使用 `--all`。
它会解析大量可能相互冲突的原生包和 CUDA 包，成本远高于按预设安装。

### 5.5 复制并检查配置

生产环境不要就地编辑已跟踪的预设。
请在源代码树之外生成部署副本，例如：

```text
/etc/openavatarchat/config.yaml
/etc/openavatarchat/openavatarchat.env
/etc/openavatarchat/tls/fullchain.pem
/etc/openavatarchat/tls/privkey.pem
```

至少审查：

- `service.host` 和 `service.port`；
- TLS 终止方式；
- `chat_engine.model_root`；
- `chat_engine.concurrent_limit`；
- 每个已启用的处理程序和模块；
- 每个 API 端点/模型名称；
- 数字人资源与模型路径；
- `RtcClient.connection_ttl`；
- `RtcClient.output_video_fps`；
- TURN 配置（如果使用）；
- 如果路由没有得到保护，则必须禁用 Manager。

配置边界情况：

- `OPEN_AVATAR_CHAT_CONFIG` 会覆盖 CLI 的 `--config` 值。
- 大多数引擎路径中的相对路径从项目根目录解析，但部分第三方代码仍假定其预期的目录布局。
- MuseTalk 要求 `RtcClient.output_video_fps` 等于 `AvatarMusetalk.fps`；随附 MuseTalk 预设将两者都设为 `24`。
- 其他数字人模式没有同样的运行时一致性校验。
  部分随附的 LiteAvatar/FlashHead 预设将数字人 FPS 设为 `25`，而 RTC 保留默认值 `30`。
  生成 FPS 与调度 FPS 只要不一致，就应视为集成风险，并通过长时间音视频同步测试验证实际影响。
- MuseTalk FPS 必须为 `1..49` 且应能整除 24,000；支持/建议值包括 15、16、20、24、25、30、32、40 和 48。
- MuseTalk `batch_size` 必须至少为 2。
- YAML 中的双工模式 `history` 设置目前不会影响运行时行为。
- 每个处理程序的 `concurrent_limit` 会被引擎级值覆盖。

### 5.6 准备凭据与密钥

常规云预设需要：

```text
DASHSCOPE_API_KEY
```

可选路径可能需要：

```text
DIFY_API_KEY
SEMANTIC_LLM_EAS_TOKEN
INTERRUPT_JUDGE_LLM_EAS_TOKEN
```

使用部署平台的密钥管理器，或使用仅 root 用户和服务用户可读的环境文件：

```bash
sudo install -d -m 0750 -o openavatarchat -g openavatarchat /etc/openavatarchat
sudo install -m 0600 -o openavatarchat -g openavatarchat \
  /path/to/prepared.env /etc/openavatarchat/openavatarchat.env
```

不要：

- 提交 `.env`；
- 将真实密钥粘贴到 shell 历史记录中；
- 将密钥烘焙进镜像；
- 在启用 Manager 的 YAML 中内联 API 密钥；
- 在可以使用环境变量或密钥注入机制时，仍通过可读写容器挂载暴露 `.env`。

当前日志记录器会记录完整会话文本和 TURN 配置。
在日志完成脱敏前，请保护日志并避免使用静态 TURN 凭据。

### 5.7 使用实际加载器验证 YAML

创建环境后，使用实际的 Dynaconf/Pydantic 路径：

```bash
PYTHONPATH=src .venv/bin/python -B - /etc/openavatarchat/config.yaml <<'PY'
import sys
from types import SimpleNamespace
from service.service_utils.service_config_loader import load_configs

path = sys.argv[1]
logger_config, service_config, engine_config = load_configs(
    SimpleNamespace(config=path, env="default")
)
print("service", service_config.host, service_config.port)
print("model_root", engine_config.model_root)
print("handlers", sorted((engine_config.handler_configs or {}).keys()))
PY
```

然后在不安装的情况下验证依赖发现：

```bash
.venv/bin/python -B install.py \
  --config /etc/openavatarchat/config.yaml \
  --dry-run
```

两项检查缺一不可。
安装程序使用另一套 YAML 解析器，会接受实际运行时加载器拒绝的 Qwen 重复键。

### 5.8 启用证书采集受集成与资格验证双重门禁

证书采集是可选功能，默认值为 `false`。
启用后会改变应用路由和安全行为，因此应复制预设并显式增加 service 配置，不要隐式修改共享部署：

`AdmissionNoticeExtractorV1`、`HbtcAdmissionNoticeTemplateMatcherV1` 和私有编排服务的精确边界，以及它们为何不是生产启用入口，详见[录取通知书字段提取模块参考](certificate-extractor.md)。

```yaml
default:
  service:
    host: "0.0.0.0"
    port: 8282
    workers: 1
    cert_file: "/etc/openavatarchat/tls/fullchain.pem"
    cert_key: "/etc/openavatarchat/tls/privkey.pem"
    certificate_capture:
      enabled: true
      oidc:
        issuer: "https://identity.example.com/"
        jwks_url: "https://identity.example.com/.well-known/jwks.json"
        audience: "openavatarchat"
        allowed_algorithms:
          - "ES256"
        required_scope: "certificate:capture"
```

以上值只是占位符，仓库没有随附身份提供商。
issuer 和 JWKS URL 必须是绝对 HTTPS URL。
Access token 必须使用显式允许的非对称算法签名，采用精确 `typ=at+jwt`，匹配 issuer/audience，包含有效的时间与 subject claim，并携带按用途限定的 scope。
`certificate:capture` 用于证书/会话控制和前端初始化配置；版本/健康探针、Manager HTTP 操作及 Manager WebSocket 票据签发则独立要求 `oac:manager`。
两种 scope 不能互换。

如果 OIDC 缺失/无效、TLS 材料缺失/不可读/加密/不匹配、`workers` 或 `WEB_CONCURRENCY` 不精确等于一，或传统 Gradio/RTC 路由发生冲突，启用模式会失败关闭。
该模式挂载经认证的会话控制、应用自有 RTC 信令、票据绑定 WebSocket 准入、五条私有采集路由和 Manager 授权。
静态 UI 资产仍可公开读取；静态交付不等于获得后端资源授权。
启用模式的 Manager 客户端使用带 `oac:manager` 的 Bearer token 调用 `POST /api/v1/manager/websocket-admission-tickets` 获取一次性 WebSocket 票据，再发送且只发送一个 Manager `Sec-WebSocket-Protocol` token：`oac.manager-admission.v1.<admission_ticket>`。
只发送原始票据会被拒绝，签发响应为 `no-store`。

这只会启用安全采集控制，不会启用成功的生产文档处理。
在当前 HEAD，`SealCapture` 只检查构造器注入的测试 processor，并且只启动 mock processor 操作；它不会调用已安装的私有 OCR 或提取服务。
因此，即使存在有效 OCR 部署清单和健康 sidecar，通过三张唯一帧门禁后的生产请求仍返回 `PROCESSOR_NOT_READY`。
M6A–M7 组件是经过隔离验证的 owner-only seam，不是生产 Seal 管线。

唯一支持的采集 profile 是：

| 项目 | 精确值 |
|---|---|
| 模板 | `hbtc_admission_notice_v1` |
| 可信学校 | `湖北交通职业技术学院` |
| 提取字段 | `name`、`source_province`、`college`、`major` |
| 字段结果 | `FOUND`、`AMBIGUOUS`、`NOT_FOUND` |
| 释放策略 | `admission-notice-safe-release.v1` |

学校名称由服务端持有，不是 OCR 输出。
模板 `MATCHED` 只表示文本和布局与固定解析器兼容，不代表真实性、发行方或录取状态已验证。
系统没有任意 profile 注册表，也不提供公共 OCR/提取/结果端点。

未来任何生产组合还必须经过独立的硬资格门禁。
下列内容必须来自经过审查的隔离 CPU 资格验证：

- 获批且冻结哈希的 sidecar `uv.lock`；
- 精确的只读 PP-OCRv6 模型产物和字典/配置哈希；
- 完整 CPU-only `InferenceIdentityV1` 及资格验证记录；
- 针对每类生产 CPU 的精度、延迟、RSS、线程/进程和实时争用测量证据；
- 严格的本地 `oac.certificate-ocr-deployment.v1` 清单，使用绝对路径，且文件不能被 group/world 写入；
- 相互匹配的 UDS 路径、mode、sidecar UID/GID `10001:10001`、主进程 peer 身份和固定超时预算。

只有具备这些输入后，部署才可用下列变量暂存严格候选：

```bash
export OPENAVATAR_CERTIFICATE_OCR_DEPLOYMENT_MANIFEST=\
/etc/openavatarchat/certificate-ocr-deployment.json
```

清单只包含身份、哈希、UDS 策略和超时，不包含 token、能力、图像路径或 OCR 文本。
输入缺失、冲突、不健康或未通过资格验证时，普通 OpenAvatarChat 仍可运行，但证书 OCR 保持不可用。
有效候选仍不会把当前 Seal 连接到 OCR；设置该变量不是生产采集启用步骤。

根 Compose profile 展示所需的隔离形态：`network_mode: none`、无端口、root 与模型挂载只读、有界 tmpfs、OCR 进程移除全部 capability，并由单独的无网络一次性任务初始化卷。
可用下列命令检查渲染后的结构：

```bash
docker compose --profile certificate-ocr config --no-interpolate
```

不要直接从当前检出版本启动该 profile 作为生产服务。
镜像被刻意标记为 `unqualified`；仓库缺少获批锁文件/模型/资格验证，而且仅选择该 profile 并不会向主服务注入生产部署清单，生产 Seal 也没有 OCR/提取调用路径。

M8 增加了固定 profile 的 WebUI 流程，可处理 1–3 张仅保存在内存中的 JPEG。
它不会执行浏览器本地 OCR，也不会显示 OCR/提取数据。
在当前检出版本中，足够帧数后的唯一生产结果是 `PROCESSOR_NOT_READY`，随后执行 EndCapture，并清理浏览器侧相机、照片和能力。
仅完成资格验证也不会改变这一点；生产组合同样缺失。
隐藏成功开关、构造器注入的测试 processor、合成清单或 fallback backend 都不能作为部署规避方案。

## 6. 原生 Linux 部署

### 6.1 安装系统包

在 Ubuntu 22.04 上：

```bash
sudo apt-get update
sudo apt-get install -y \
  git git-lfs build-essential curl ca-certificates openssl \
  libgl1 libglib2.0-0 libsm6 libxext6 libgomp1 \
  libsndfile1 ffmpeg sox libsox-dev \
  libavcodec-dev libavformat-dev libswscale-dev
```

从已批准的来源安装 `uv`。
在生产构建中，应固定并验证安装程序/包版本，不要执行浮动的远程安装脚本。

```bash
uv --version
uv python install 3.11
uv venv --python 3.11 --seed
.venv/bin/python --version
```

生成的 Python 必须至少为 3.11.7 且低于 3.12。

### 6.2 只安装目标预设所需的处理程序

示例：

```bash
uv run install.py \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml
```

对于多个已批准预设：

```bash
uv run install.py \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml \
  --config config/chat_with_openai_compatible_bailian_cosyvoice_duplex.yaml
```

安装过程中会从源代码编译部分软件包。
FlashHead 的 `flash-attn` 构建最多使用四个并行任务，但仍需要充足的内存和构建时间，并确保 CUDA 编译器兼容。

记录以下发布证据：

```bash
.venv/bin/python --version
uv pip freeze
nvidia-smi
```

生成的本地 `uv.lock` 被此仓库忽略；在建立已跟踪的锁定工作流前，请单独归档经过审查的依赖清单。

### 6.3 下载模型

统一模型下载器不支持试运行（`dry-run`），并且可能自动安装缺少的下载工具。
以下命令会访问网络并写入文件：

```bash
uv run scripts/download_models.py \
  --config /etc/openavatarchat/config.yaml \
  --source huggingface
```

或者，对于已知处理程序：

```bash
uv run scripts/download_models.py --handler liteavatar
uv run scripts/download_models.py --handler smart_turn_eou
uv run scripts/download_models.py --handler musetalk
uv run scripts/download_models.py --handler flashhead
uv run scripts/download_models.py --handler lam
```

在已实现的位置，`--source modelscope` 会选择 ModelScope 或已配置的镜像路径。
选择来源并不等同于验证产物。

LiteAvatar 权重与具体数字人资源相互独立。
请提前下载配置中选择的数字人资源：

```bash
uv run scripts/download_avatar_model.py \
  --model 20250408/sample_data
```

这样可以避免数字人处理程序在第一个会话中临时下载资源。
该命令还会生成随附 MuseTalk 双工预设所需的 `bg_video_silence.mp4`。

重要的自动下载情形：

- SenseVoice 可能在处理程序加载期间通过 ModelScope 下载。
- 部分本地第三方组件可能自行获取检查点。
- 目录存在并不能证明所有预期文件都存在。

对于生产环境，只有在干净主机演练已识别并镜像每个产物后，才应在禁用出口访问的情况下运行。

### 6.4 验证目标模型文件

至少按路径执行以下检查：

```bash
test -s models/smart_turn/smart-turn-v3.1-cpu.onnx
test -d models/SoulX-FlashHead-1_3B
test -d models/wav2vec2-base-960h
test -d models/musetalk
test -s resource/avatar/liteavatar/20250408/sample_data/bg_video_silence.mp4
test -s resource/avatar/flashhead/girl.png
```

只运行适用于目标预设的检查。
这些命令只能确认文件存在，不能验证文件完整性；还应根据已批准的清单校验 SHA-256。

对于 MuseTalk，请确认已配置的源视频存在，且 S3FD 检查点可通过原生运行和容器运行所预期的路径/缓存访问。

### 6.5 本机冒烟测试

安装完成后使用 `--no-sync` 启动，避免运行过程中修改环境：

```bash
set -a
. /etc/openavatarchat/openavatarchat.env
set +a

uv run --no-sync src/demo.py \
  --config /etc/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
```

如果在本机使用 HTTP：

```text
http://localhost:8282/
```

对于直接 Uvicorn TLS：

```text
https://localhost:8282/
```

只有当日志明确出现 `SSL enabled`，且客户端信任证书、证书主机名也有效时，才能使用 HTTPS。

检查：

```bash
curl --fail http://127.0.0.1:8282/version
curl --fail http://127.0.0.1:8282/liveness
curl --fail http://127.0.0.1:8282/readiness
```

对于 TLS 监听器，改用 `https://`。
仅在明确的自签名开发测试中可以使用 `curl -k`，绝不能将其用作生产验证。

### 6.6 专用服务进程

使用专用的非特权用户，并只运行一个进程。
以下是可作为起点的 systemd 单元：

```ini
[Unit]
Description=OpenAvatarChat
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openavatarchat
Group=openavatarchat
WorkingDirectory=/opt/openavatarchat
EnvironmentFile=/etc/openavatarchat/openavatarchat.env
ExecStart=/opt/openavatarchat/.venv/bin/python \
  /opt/openavatarchat/src/demo.py \
  --config /etc/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
Restart=always
RestartSec=5
TimeoutStopSec=60
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/openavatarchat/logs
ReadWritePaths=/opt/openavatarchat/temp
ReadWritePaths=/opt/openavatarchat/build
ReadWritePaths=/opt/openavatarchat/exp

[Install]
WantedBy=multi-user.target
```

应根据部署环境明确设置 GPU 设备权限，以及模型和缓存的可写路径。
在依赖平滑关闭机制前，必须测试存在活动会话时的 SIGTERM 行为；当前引擎在关闭时不会显式停止所有会话。

这里特意使用 `Restart=always`：`src/demo.py` 会把启动失败转换为退出码 `0`，因此 `Restart=on-failure` 无法触发重启；`systemctl stop` 仍会阻止策略性重启。
部署验收不能只看退出码，必须探测 `/readiness`，并核对已注册处理程序是否与批准的配置一致。

不要配置多个 Uvicorn worker。

## 7. 独立 Docker 部署

### 7.1 构建前检查

构建前：

- 初始化每个子模块；
- 确保 Docker 可以访问 NVIDIA 运行时；
- 确保目标镜像仓库和镜像源已经批准且可以访问；
- 为包含原生编译的全处理程序 CUDA 构建预留资源；
- 确认镜像构建没有使用受版本控制的锁文件；
- 修正宽泛的 `.dockerignore` 规则；这些规则会排除所有 `*.yaml` 和 `*.yml`，包括 `src/` 下的运行时文件。

当前构建上下文无法完整包含依赖 YAML 的处理程序。
例如，FlashHead 会导入 `src/handlers/avatar/flashhead/SoulX-FlashHead/flash_head/configs/infer_params.yaml`，而当前忽略规则会在 `COPY ./src` 前移除该文件。
不要将镜像构建成功用作 FlashHead、LiteAvatar、MuseTalk 或本地 CosyVoice 已就绪的证据。
请把忽略范围限定到实际的部署/Kubernetes 文件，或明确重新纳入 `src` 下的运行时 YAML，然后测试最终镜像。

使用明确的不可变标签构建：

```bash
bash build_cuda128.sh \
  --tag open-avatar-chat:6db2b96
```

构建脚本默认使用 `open-avatar-chat:latest`，运行脚本也把该标签写死。
测试其他标签时，应直接执行 `docker run`，或先明确地重新标记镜像。

当前构建脚本只应接收可信的 `--tag` 和 `--push` 参数。
它会拼接 shell 字符串并通过 `eval` 执行；在改用参数数组之前，不要把分支名、拉取请求数据或其他用户输入传给它。

不要将镜像构建成功视为模型就绪。
模型和运行时资源从主机挂载。

### 7.2 检查镜像

```bash
docker image inspect open-avatar-chat:6db2b96
docker history --no-trunc open-avatar-chat:6db2b96
docker run --rm --entrypoint test \
  open-avatar-chat:6db2b96 \
  -s /root/open-avatar-chat/src/handlers/avatar/flashhead/SoulX-FlashHead/flash_head/configs/infer_params.yaml
docker run --rm --gpus all \
  --entrypoint uv \
  open-avatar-chat:6db2b96 \
  run --no-sync python -c \
  "import sys, torch; print(sys.version); print(torch.__version__); print(torch.cuda.is_available())"
```

仅对支持 FlashHead 的镜像运行 YAML 存在性检查，并为所选处理程序增加等效的精确资产检查。

对于受控发布，应把镜像推送到不可变镜像仓库，并记录内容摘要。
Dockerfile 中的 `APP_VERSION` 只是元数据，不能唯一标识镜像内容。

### 7.3 运行标准预设

仓库的运行脚本使用主机网络模式：

```bash
bash run_docker_cuda128.sh \
  --config config/chat_with_openai_compatible_bailian_cosyvoice.yaml
```

在 Linux 上使用 `--network=host` 时，`-p 8282:8282` 不会生效，进程直接绑定主机端口。

为便于生产管控，建议使用显式命令，让镜像、挂载和环境参数一目了然：

```bash
docker run --rm --gpus all \
  --name open-avatar-chat \
  --network host \
  --env-file /etc/openavatarchat/openavatarchat.env \
  -e NVIDIA_VISIBLE_DEVICES=all \
  -e NVIDIA_DRIVER_CAPABILITIES=compute,video,utility \
  -v /srv/openavatarchat/models:/root/open-avatar-chat/models \
  -v /srv/openavatarchat/resource:/root/open-avatar-chat/resource \
  -v /srv/openavatarchat/build:/root/open-avatar-chat/build \
  -v /srv/openavatarchat/exp:/root/open-avatar-chat/exp \
  -v /srv/openavatarchat/logs:/root/open-avatar-chat/logs \
  -v /etc/openavatarchat/config.yaml:/run/openavatarchat/config.yaml:ro \
  -v /etc/openavatarchat/tls:/etc/openavatarchat/tls:ro \
  open-avatar-chat:6db2b96 \
  --config /run/openavatarchat/config.yaml \
  --host 127.0.0.1 \
  --port 8282
```

使用主机网络模式时，如果由主机上的反向代理提供公网入口，可将应用绑定到 `127.0.0.1`。
如果客户端直接从受信任局域网连接，则必须明确调整绑定地址和防火墙规则。

镜像目前以 root 用户运行。
在修复镜像前，应尽量缩小暴露面，并把配置和 TLS 文件以只读方式挂载。
只有在所有处理程序都已证明不会在运行时向模型/资源挂载下载、解压、预处理或写入缓存后，才能将这些挂载设为只读。

### 7.4 MuseTalk 的 Docker 配置

辅助程序通过文本检测 MuseTalk，并添加：

```text
PYTORCH_JIT=0
```

它还会将 S3FD 模型目录挂载到 Torch 的检查点缓存中。
请确认：

- 配置包含辅助程序预期的精确 `AvatarMusetalk` 模块路径；
- `RtcClient.output_video_fps == AvatarMusetalk.fps`；
- 数字人源视频位于挂载路径内；
- S3FD 主机目录是一个包含预期检查点的目录；
- `/dev/shm` 足以满足测得的工作负载。

Compose 文件设置 2 GB 共享内存；独立辅助程序未显式设置 `--shm-size`。
需要时请添加经过测量的值。

### 7.5 Beta Agent 镜像限制

当前 Dockerfile 不会在执行 `install.py --all` 前复制 Agent 处理程序的依赖清单，因此依赖层不会安装 `mcp`。
不要把标准镜像描述为支持 Beta Agent 预设。

## 8. Docker Compose 与 TURN

### 8.1 现有 Compose 配置的状态

以下命令只验证 Compose 语法和变量插值：

```bash
docker compose config --no-interpolate
```

它不会验证主机绑定挂载源、证书与密钥是否匹配、coturn 选项语法、TURN 凭据、中继可达性或浏览器 ICE 行为。

审查时的检出版本尚不满足启动前提，因为以下绑定挂载源不存在：

```text
.env
ssl_certs/localhost.crt
ssl_certs/localhost.key
models/musetalk/s3fd-619a316812/
```

即使对于非 MuseTalk 预设，S3FD 挂载也无条件存在。

### 8.2 使用 Compose 前必须完成的修正

1. 将 `coturn/coturn` 固定到已批准的版本或摘要。
2. 替换 `user=admin:admin`。
3. 用已部署的 TURN 主机名替换示例 realm。
4. 将 `min-port:49152` 和 `max-port:65535` 改为 coturn 赋值语法（`min-port=...`、`max-port=...`），并使用所选 coturn 镜像验证。
5. 把真正的私钥挂载到 `/etc/turn_key.pem`，不能挂载证书。
6. 以只读方式挂载证书/密钥/配置。
7. 添加配额、监控和明确限定的 UDP 中继端口范围。
8. 审查/移除 `allowed-peer-ip=0.0.0.0`；不要假定它是安全的通用生产策略。
9. 添加健康检查。
10. 向所选应用的 `RtcClient` 添加 TURN 配置。
11. 移除无关的 MuseTalk 缓存挂载，或使其成为条件挂载。
12. 将应用置于经身份验证的入口之后；不要直接公开应用。

修正后的密钥挂载在概念上应为：

```yaml
volumes:
  - ./coturn-data/turnserver.conf:/etc/coturn/turnserver.conf:ro
  - ./ssl_certs/turn-fullchain.pem:/etc/turn_cert.pem:ro
  - ./ssl_certs/turn-privkey.pem:/etc/turn_key.pem:ro
```

### 8.3 为应用配置 TURN

只启动 TURN 容器还不够。
部署流程还必须为已启用的 RTC 客户端生成以下配置块：

```yaml
default:
  chat_engine:
    handler_configs:
      RtcClient:
        module: client/rtc_client/client_handler_rtc
        connection_ttl: 900
        turn_config:
          turn_provider: turn_server
          urls:
            - "turn:turn.example.com:3478?transport=udp"
            - "turn:turn.example.com:3478?transport=tcp"
            - "turns:turn.example.com:5349?transport=tcp"
          username: "<deployment-generated-user>"
          credential: "<deployment-generated-secret>"
```

静态 TURN 凭据按设计会发送到浏览器，因此客户端一定能够看到。
如条件允许，应改用托管或动态提供程序生成的短期凭据。
当前静态提供程序不会签发临时 TURN REST 凭据。

RTC 提供程序当前会以 INFO 记录此配置块，包括凭据。
在修复该日志记录前，不要认为静态密钥受到保护。

### 8.4 TURN 防火墙

根据实测并发量选择尽可能小的中继端口范围，并确保 coturn 配置与防火墙完全一致。

| 协议 | 端口/范围 | 用途 |
|---|---:|---|
| UDP | 3478 | TURN 主要传输 |
| TCP | 3478 | TURN 回退 |
| TCP/TLS | 5349 | TURN-over-TLS 回退 |
| UDP | 已配置的有限中继端口范围 | 已分配的中继媒体 |

RFC 8656 规定了 3478/5349 端口的惯例，并建议使用 49152–65535 动态端口范围。
在正确评估容量并持续监控的前提下，采用更小且经过明确规划的范围可以减少暴露。
参见 [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656.html)，该规范取代了 RFC 5766 和 RFC 6156。

还应配置：

- 适用于 NAT 的正确 `external-ip`/中继地址；
- 安全组与主机防火墙的对称规则；
- 确保对外发送的 ICE 候选项不会意外包含私网地址或容器地址；
- 分配/带宽配额；
- 凭据轮换/撤销；
- 记录来源和分配信息时不得包含密钥；
- 针对分配量、带宽、身份验证失败和端口耗尽的告警。

请针对所选精确版本使用[coturn 配置参考](https://github.com/coturn/coturn/blob/master/README.turnserver)。
避免使用 `server-relay` 和仅供开发使用的对等方放宽选项。

### 8.5 外网验收测试

仅在回环地址上使用浏览器时，无法验证 TURN。
请通过独立的公网连接进行测试：

1. 打开受信任的 HTTPS 应用 URL；
2. 授予相机/麦克风权限；
3. 启动一次会话；
4. 检查 `chrome://webrtc-internals` 或等效的浏览器诊断工具；
5. 在强制/需要中继时，确认选择了 `relay` ICE 候选项；
6. 分别测试 UDP、TCP 和 TLS 回退策略；
7. 停止 coturn，并确认外部 TURN 探针或 TURN 专用告警触发；内置应用 `/readiness` 端点应继续返回 `200`，因为它不检查 TURN；
8. 确认凭据能够轮换，旧凭据会到期。

## 9. TLS

### 9.1 公网部署的推荐架构

在监听 TCP 443 的反向代理或入口处终止受公网信任的 TLS。
OpenAvatarChat 只通过 HTTP 监听回环地址或私有网络。
在部署使用的配置副本中，应省略 `service.cert_file` 和 `service.cert_key`，或把它们设为 `null`，明确表示内部链路使用明文，避免把证书缺失后的静默回退误当作预期配置。

代理必须支持：

- HTTP 请求和 WebSocket 协议升级；
- 长时间运行的信令连接；
- 为流式传输禁用响应缓冲，或进行谨慎调优；
- 足够长的空闲/读取超时；
- 在建立信令连接或创建会话前完成身份验证；
- 速率和并发会话限制；
- 受信任的 `Host` 和 WebSocket `Origin` 验证；
- 在 HTTP 与 WebSocket 会话创建流程中安全处理 CSRF、cookie 和 token；
- 正确的转发标头；
- 对令牌/查询字符串进行访问日志脱敏；
- 如果明确需要公开 Manager，保护范围必须覆盖全部 FastRTC 和 Manager 路径。

由于 WebRTC 媒体本身可能是对等/中继流量，反向代理不能替代 TURN。

### 9.2 由 Uvicorn 直接终止 TLS

如果应用终止 TLS，请同时设置：

```yaml
service:
  cert_file: "/etc/openavatarchat/tls/fullchain.pem"
  cert_key: "/etc/openavatarchat/tls/privkey.pem"
```

当前实现会在任一文件路径缺失时静默启动明文服务。
只要出现以下日志，就应判定部署失败：

```text
Cert file ... not found
Key file ... not found
```

只有出现以下明确日志，才能确认 TLS 已启用：

```text
SSL enabled.
```

### 9.3 证书预检

```bash
openssl x509 -in fullchain.pem -noout -subject -issuer -dates
openssl x509 -in fullchain.pem -noout -ext subjectAltName
openssl pkey -in privkey.pem -check -noout
```

比较公钥：

```bash
openssl x509 -in fullchain.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  sha256sum

openssl pkey -in privkey.pem -pubout -outform DER |
  sha256sum
```

两个哈希必须匹配。

`scripts/create_ssl_certs.sh` 会以交互方式创建有效期一年的 `localhost` 自签名证书，但不会显式配置 SAN。
该证书仅适用于开发环境；局域网或公网部署应使用包含真实主机名、由内部或公共 CA 签发的证书。

## 10. 公网生产拓扑

```text
Internet browser
      |
      | HTTPS / WSS :443
      v
Authenticated reverse proxy
      |
      | private HTTP :8282
      v
Single OpenAvatarChat process ----> approved cloud APIs/models
      |
      | optional private UDS
      v
Qualified CPU OCR sidecar (no network, no GPU)
      |
      | ICE configuration
      v
Hardened TURN host
  :3478 UDP/TCP
  :5349 TLS
  bounded UDP relay range
```

必需的生产门槛：

- 应用端口只能从入口/管理网络访问；
- 在 UI/信令/Manager 之前执行服务端身份验证；
- 启用证书模式时：严格 OIDC scope、单 worker、经认证的 WS/RTC/采集/Manager 准入，以及采集路由隔离；
- 经过审查的生产 Seal→OCR/提取/释放组合，不使用构造器注入的测试 processor；
- 按用户和全局会话配额；
- 使用非 root 用户运行应用容器或进程；
- 不可变镜像摘要和依赖/模型清单；
- 在最终镜像内验证所选处理程序的运行时资产；
- 独立于进程退出码的明确就绪证据；
- 移除或隔离模型 pickle 风险；
- 有界且事件循环安全的 RTC 队列；
- 受信任 TLS，并在 TLS 校验失败时阻止启动；
- 使用非公开凭据的加固 TURN；
- 禁用 Manager 或单独授权；
- 转录内容/日志/媒体保留策略；
- 活动会话关闭测试；
- 能感知前置条件的就绪检查；
- 按预期会话数、媒体分辨率、FPS 和网络丢包进行负载测试；
- 使用兼容的配置/模型资产演练回滚。

在满足这些门槛前，应将部署分类为受控演示，而不是生产服务。

## 11. 启动后的验收清单

### 进程与服务

- `/version` 返回预期应用版本。
- `/liveness` 和 `/readiness` 返回 200。
- 日志包含每个预期的 `Registered handler` 和 `Handler ... loaded`。
- 日志不包含证书/密钥/模型/API 缺失警告。
- 进程以预期 UID 运行，并且仅具有预期挂载。
- 部署自动化必须检查明确的就绪状态，不能仅凭退出码 `0` 判定成功。

### GPU/媒体

- `nvidia-smi` 显示预期进程和 GPU。
- 单个会话可以完成麦克风输入、ASR 文本、响应文本、音频和数字人视频的完整链路。
- 音频和视频至少在一个已配置的连接 TTL 窗口内保持同步。
- 对于双工预设，手动中断和语义中断均能正常工作。
- 慢速/断开连接的客户端不会导致内存无界增长。
  这是必需测试，因为当前实现没有队列边界。

### 网络/安全

- 阻止不受信任网络直接访问 `8282`/`8283`。
- 拒绝未经身份验证的入口访问。
- WebSocket 协议升级能够通过代理完成。
- HTTPS 证书链和主机名无需绕过即可验证。
- Manager 端点不存在或受授权保护。
- TURN 中继候选项可从外部受限网络工作。
- 仓库中的默认 TURN 凭据已被禁用或拒绝。

### 持久化/运维

- 日志发送到预期的受保护接收端，且不包含密钥。
- 可写目录的容量受到限制并已纳入监控。
- 重启仅丢失已记录的内存会话状态。
- 已记录模型/配置/镜像摘要。
- 回滚产物可用且已测试。

### 启用安全证书采集时

- 启动会拒绝缺失/不匹配 TLS、无效 OIDC 和多 worker；
- 未认证、错误 scope、重放、错误会话和错误采集请求不会创建会话/采集副作用；
- `/version`、`/liveness`、`/readiness` 和初始化配置使用正确授权 scope 探测，而不是匿名访问；
- M8 浏览器把照片/能力保留在内存中，在所有取消/错误/End 路径撤销 Object URL，并恢复普通相机轨道；
- OCR 容器没有网络、端口、GPU/CUDA 初始化、可写模型/root 文件系统或非预期 UDS peer；
- 在未来生产组合中，EndCapture 会在任何一次性净化 ChatAgent 回合前销毁采集 DEK 并退役陈旧工作；
- 日志与支持包不包含 JPEG、OCR 文本、提取值、token、能力、prompt 上下文或私有存储身份；
- 当前生产 Seal 无论是否有清单都返回 `PROCESSOR_NOT_READY`；如果通过测试 processor 表现出生产成功，应按发布失败处理。
  后续版本必须同时证明组合与资格验证。

有关持续运行手册的详细信息，请参见[运维与验证](operations-validation.md)。
