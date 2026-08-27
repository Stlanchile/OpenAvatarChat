# OpenAvatarChat 运维、故障排查与验证

**语言：** 简体中文 · [English](../operations-validation.md)

## 1. 运维模型

OpenAvatarChat 虽然不依赖数据库，但仍然是一个有状态的实时服务：

- 模型实例和已注册处理程序在进程生命周期内存活；
- 会话、数据流图、对话历史、队列和 Manager 缓冲区都保存在进程内存中；
- 每个会话会为每个启用的处理程序创建一个队列处理线程；
- 每个会话会创建一个信号分发线程；
- WebRTC 会增加事件循环任务和媒体队列；
- 所选数字人处理程序还会创建各自的工作线程、进程或 GPU 状态；
- 启用证书模式的会话还会增加代际权威、采集协调、采集密钥加密证据，以及可选的隔离 CPU OCR 进程；
- 重启会终止所有会话并丢弃内存中的历史记录。

`src/demo.py` 现在会为显式的证书配置/启动门禁失败保留非零状态，但仍通过 `os._exit()` 结束，也可能掩盖其他启动失败。
监督程序、CI 和 shell 自动化必须检查明确的就绪状态，并核对日志与处理程序，不能把退出码 `0` 直接解释为成功。

每个已分配 GPU 的服务实例只运行一个应用进程。
如需扩展，应使用带准入控制的隔离实例，在用户之间进行明确隔离，而不是为单个应用进程增加 Uvicorn worker。

## 2. 健康检查端点及其准确含义

| 端点 | 成功时可以确认 | 启用模式授权 | 仍然不能确认 |
|---|---|---|---|
| `/version` | HTTP 应用能够响应，并返回硬编码的应用版本 | 带 `oac:manager` 的 Bearer token | Git 提交、镜像、模型或配置的具体版本 |
| `/liveness` | FastAPI 进程和事件循环能够响应简单请求 | 带 `oac:manager` 的 Bearer token | 处理程序线程、GPU、TURN、模型、OCR 或 API 连通性 |
| `/readiness` | `ChatEngine.initialize()` 已完成，且 `inited` 已设置 | 带 `oac:manager` 的 Bearer token | 浏览器 RTC/采集链路、凭据、模型完整性、TURN、生产 OCR 组合/资格或容量 |

以下匿名探针仅适用于私有监听器后的传统/默认模式：

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8282/liveness

curl --fail --silent --show-error \
  http://127.0.0.1:8282/readiness

curl --fail --silent --show-error \
  http://127.0.0.1:8282/version
```

当 Uvicorn 终止 TLS 时，使用 HTTPS 和正常的证书验证。
不要在生产探针中使用 `-k`。

启用证书模式时，应使用严格保管的 `oac:manager` 探针 token 和配置的 HTTPS 主机名：

```bash
read -r OAC_MANAGER_ACCESS_TOKEN < /run/secrets/oac-manager-token
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${OAC_MANAGER_ACCESS_TOKEN}" \
  https://chat.example.com/liveness
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${OAC_MANAGER_ACCESS_TOKEN}" \
  https://chat.example.com/readiness
unset OAC_MANAGER_ACCESS_TOKEN
```

不要把 token 写入 URL、命令历史、探针输出或指标。

针对具体部署的就绪门槛还应检查：

- 目标预设所需的具体模型文件和已批准哈希；
- CUDA 设备可用性及一次小型、非破坏性的分配/推理；
- 直接使用 TLS 时，证书与密钥是否存在、是否匹配，以及主机名和有效期是否正确；
- 所需 API 密钥存在，但不记录其值；
- 所选云处理程序的 DNS/TCP/TLS 可达性；
- 在需要 TURN 时的 TURN 分配/中继路径；
- 磁盘空间和可写的输出/缓存路径；
- 当前会话数是否低于准入阈值；
- 启用模式 OIDC/JWKS 可达性和精确路由清单；
- 在未来完成集成的版本中，检查 OCR 部署清单、身份、锁/模型/资格验证哈希、UDS owner/mode/peer 和 sidecar 健康；
- 当前检出版本的所有生产 Seal 均明确预期 `PROCESSOR_NOT_READY`，因为 Seal 尚未与 OCR/提取组合；该结果与是否存在合格 OCR 输入无关。

当前应用未实现这些更深入的检查。

## 3. 启动日志检查清单

可以确认启动成功的日志：

```text
Load config with env ...
Registered handler ...
Handler ... loaded in ... milliseconds
Serving frontend from ...
SSL enabled.                       # only for direct TLS
Service will be started on ...
```

以下日志表示启动失败或服务处于降级状态：

```text
Config file ... not found
Failed to parse handler config
Failed to import module
Cert file ... not found
Key file ... not found
No valid rtc provider configuration found
model ... not found
api_key=[EMPTY]
CUDA out of memory
Certificate capture startup preflight failed (...)
CERTIFICATE_OCR_UNAVAILABLE_V1
```

部分处理程序发生运行时异常后，应用仍会继续运行；传统模式下 TLS 文件缺失时，服务也会明确回退后继续启动。
启用模式下证书预检失败属于致命错误；仅日志诊断 `CERTIFICATE_OCR_UNAVAILABLE_V1` 表示部署候选无效或冲突，普通对话仍会运行。
无论如何，当前 Seal 不会调用 OCR/提取，因此生产证书处理不可用。
仅看到 PID 存活不足以证明启动成功。

## 4. 日志与隐私管理

日志记录器写入：

- 按配置级别输出到 stdout；
- `logs/log.log`，在 10 MB 时轮转并保留十个轮转文件。

标准 LLM 处理程序会把完整的用户识别文本和生成结果写入 INFO 日志。
Manager 模式会在 `temp/data_tool` 下写入音频/图像文件。
启用时，TURN 配置（包括静态凭据）会以 INFO 记录。

生产控制措施：

1. 默认不记录转录文本和内容，只有明确需要时才启用；
2. 在结构化或文本日志记录前对 API/TURN 令牌进行脱敏；
3. 设置限制性的 umask 和服务所有的日志目录；
4. 除 Loguru 自身轮转外，还应配置容器或系统日志轮转；
5. 为转录内容、音频、图像和备份定义保留与删除规则；
6. 除非明确授权，否则将 `temp/data_tool`、日志、`.env` 和证书排除在一般支持包之外；
7. 未经脱敏，绝不在问题单中发布原始日志；
8. 在适用时验证从副本、对象存储和备份中删除；
9. 从日志、分析、崩溃报告和支持包中排除全部证书 JPEG、OCR span/全文、提取值、能力、token、prompt/context、receipt、record ID 和 capture identity；
10. 证书释放遥测仅允许包含策略版本、不透明 release ID、释放字段数、生命周期状态、耗时和稳定 reason code。

Manager 使用的内存双端队列（`deque`）有容量上限，但审查范围内的代码没有为其写入的媒体文件设置自动清理周期。
只有在规范化目标目录，并确认没有活动会话正在使用相关文件后，才能增加按时间或容量清理的外部任务。

## 5. 容量与资源管理

### 5.1 `concurrent_limit` 控制什么

引擎级别的 `chat_engine.concurrent_limit` 会复制到每个处理程序配置中，再交给客户端流实现。
它只能提供基础准入限制，并不是完整的资源调度器：

- 它不预留 GPU 内存；
- 它不限制内部 RTC 音频/视频队列；
- 它不限制每个第三方工作队列；
- 它不实施按用户划分的配额或身份验证；
- 它不在进程或主机之间协调。

没有测量结果时，绝不要将其从预设值提高。

### 5.2 测量矩阵

对于每个选定的预设，记录：

| 测量项 | 空闲 | 1 个会话 | 目标会话数 | 慢客户端 | 断开/重连 |
|---|---:|---:|---:|---:|---:|
| 已用 GPU 内存 | | | | | |
| 主机 RSS | | | | | |
| CPU 利用率 | | | | | |
| GPU 利用率 | | | | | |
| 帧率（FPS） | | | | | |
| 从语音结束到首个音频的延迟 p50/p95/p99 | | | | | |
| 5/15 分钟后的音频/视频漂移 | | | | | |
| 处理程序队列深度 | 当前不可用 | | | | |
| 错误/取消率 | | | | | |

使用实际的：

- 数字人图像/视频分辨率；
- RTC 与数字人 FPS；
- 批量大小；
- LLM/TTS 提供商和区域；
- 输入音频时长；
- `duplex` / `standard` 模式；
- 连接 TTL；
- 网络丢包与延迟条件。

历史文档中的“2.2 秒”或“每个 LiteAvatar 会话约 3 GB”等数据不能替代上述实测矩阵。

### 5.3 背压安全性

当前 RTC 音频和视频队列没有容量上限，处理程序线程还会直接写入 `asyncio.Queue`。
在修复前：

- 使用保守的并发量；
- 持续监控进程 RSS；
- 设置容器或系统内存限制，并制定重启和告警策略；
- 在入口处终止失效/缓慢会话；
- 测试网络限速和暂停的浏览器标签页；
- 对持续 RSS 增长和媒体交付停滞发出告警。

修复后，预期策略应为：

- 视频：使用有界队列，丢弃过期帧并优先保留最新帧；
- 音频：有界延迟，受控丢弃/关闭而不是无限增长；
- 文本/信号：有界、有序交付，并显式处理溢出；
- 会话：消费者连续失败时主动关闭。

## 6. 指标与告警

项目没有提供 Prometheus 或 OpenTelemetry 指标端点，至少应从外部采集：

- 进程可用性、重启和退出码；
- 就绪状态和响应延迟；
- RSS、CPU、线程、文件描述符；
- GPU 内存/利用率/温度/错误；
- 模型、日志、`build`、`exp` 和 `temp` 目录的磁盘使用量；
- 网络连接和出口流量；
- 反向代理请求/身份验证/限流统计信息；
- 活动和被拒绝的会话；
- TURN 分配、带宽、身份验证失败、中继端口利用率；
- 云 API 请求速率、延迟、错误类别和支出；
- 证书到期时间；
- 镜像、配置和模型摘要的漂移情况；
- 启用模式 OIDC 准入失败的稳定原因，不包含 token/subject；
- 采集生命周期计数、`PROCESSOR_NOT_READY`、清理失败和按稳定操作/原因聚合的 late-callback drop；
- 对于未来完成集成的部署，采集 OCR sidecar 健康、RSS/CPU/线程/进程数、请求延迟、重启、清单/身份漂移，以及任何被禁止的网络/GPU 活动；
- 对于未来完成集成的部署，采集 M7 释放结果和释放字段数，不包含字段值。

建议告警：

- 连续两个时间间隔就绪失败；
- 意外重启或 SIGKILL/OOM；
- GPU 不可用或 ECC/Xid 错误；
- RSS/GPU 内存超过已测量的安全阈值；
- 磁盘超过 80% 或异常增长；
- 证书在 30/14/7 天内到期；
- TURN 身份验证失败或分配激增；
- 云 API 401/403/429/5xx 激增；
- 直接请求到达私有应用端口；
- 来自未授权网络的 Manager 端点访问；
- 采集清理/密钥销毁失败或进入 `FAILED_CLOSED`；
- OCR 身份/资格/socket 策略漂移、非预期 sidecar 出站流量，或任何 CUDA/GPU 初始化；
- 对于未来完成集成的部署，释放策略拒绝、重放或陈旧工作丢弃持续激增。

## 7. 发布清单

每次部署都应记录以下完整发布信息：

```text
source Git commit
all submodule commits
container image repository + content digest
Python version
dependency lock/constraints digest
CUDA runtime + NVIDIA driver
selected config digest
secret version identifiers (never values)
model artifact names + immutable revision + SHA-256
avatar resource digest
frontend submodule commit/build digest
TURN version/config digest
certificate feature mode + OIDC config digest
OCR sidecar image + dependency lock digest
OCR model/identity/qualification/deployment-manifest digests
OCR UDS path/mode/expected UID/GID
deployment timestamp and operator/change record
```

仅记录应用的 `/version` 响应还不够：该值是硬编码的，而且目前与根包版本不一致。

实用命令：

```bash
git rev-parse HEAD
git submodule status --recursive
sha256sum /etc/openavatarchat/config.yaml
find models -type f -print0 | sort -z | xargs -0 sha256sum
docker image inspect --format '{{index .RepoDigests 0}}' <image>
nvidia-smi
.venv/bin/python --version
uv pip freeze
```

模型目录可能很大。
应在发布晋级时生成并保存一次清单，不要在每次健康检查时重复计算。

## 8. 备份与恢复

### 8.1 备份

只备份明确需要保留的持久化输入：

- 已完成密钥脱敏的部署配置，或经过加密并受访问控制保护的部署配置；
- 密钥管理器引用/版本；
- 已批准的模型摘要清单和获取记录；
- 无法以可复现方式重新下载的数字人资源；
- 镜像摘要、SBOM 和来源证明；
- 部署单元/Compose/入口/TURN 配置；
- 运维仪表盘/告警。

通常应从已验证的来源重建或重新下载，而不是备份：

- `.venv`；
- `__pycache__`；
- 临时 `build/`/`exp/`；
- Manager 临时媒体；
- 活动内存会话。

是否备份模型本身取决于许可、下载可用性、完整性保证和恢复时间目标。

### 8.2 恢复测试

1. 准备一台干净且兼容的 GPU 主机；
2. 恢复指定的源代码版本或镜像摘要；
3. 恢复或重新生成配置和密钥；
4. 恢复或获取模型，并验证每个摘要；
5. 验证驱动程序/运行时兼容性；
6. 在非生产私有端口启动；
7. 运行健康检查、单会话、`duplex`（如使用）、TLS 和外部 TURN 测试；
8. 仅在验收后提升流量；
9. 确认日志不包含已恢复的密钥值。

不支持跨重启的会话连续性。

## 9. 升级与回滚

### 9.1 升级

1. 冻结当前发布元组。
2. 审查源代码和每个子模块变更。
3. 在干净构建中从已批准的锁/约束解析依赖。
4. 单独获取/验证模型变更。
5. 通过真实运行时加载器验证所有选定配置。
6. 构建不可变镜像；生成 SBOM/来源。
7. 运行语法、单元、集成、浏览器 RTC、慢客户端、TURN、安全和容量测试。
8. 使用单独的会话池部署金丝雀实例。
9. 主动排空或终止现有会话；这些会话无法迁移。
10. 在观察 GPU、内存、延迟、API 错误和 TURN 指标的同时，逐步增加流量。

### 9.2 回滚

回滚需要先前的：

- 镜像摘要；
- 配置和密钥版本集合；
- 模型和数字人资源集合及摘要；
- TURN/入口兼容性；
- 驱动程序/运行时兼容性。

不能只回滚代码，却继续使用不兼容的模型或配置资源。
应先停止接收新会话，排空或终止当前会话，再启动上一套完整发布组合；验收通过后才能恢复流量。

## 10. 安全运维

### 10.1 暴露策略

- 公网：只开放带身份验证的反向代理端口 `443`，以及明确配置的 TURN 端口。
- 私有：应用监听器 `8282`/`8283`。
- 仅内部 Beta 功能：如需使用，开放回调端口 `8011`。
- 未经服务端授权，绝不公开 Manager。
- 防止容器/主机元数据和私有基础设施目标可通过配置错误的中继到达。

### 10.2 凭据轮换

独立轮换：

- 云 API 密钥；
- 入口/会话凭据；
- TURN 凭据/共享密钥；
- TLS 私钥/证书；
- OIDC 签名密钥/JWKS 及 audience/issuer 配置版本；
- 注册表凭据；
- 所有 Beta 桥接令牌。

轮换后必须验证旧凭据已经失效。
静态 TURN 凭据对浏览器客户端可见，因此长期凭据并不具备通常意义上的服务端秘密属性。

### 10.3 模型安全事件响应

如果怀疑模型来源或模型文件受到污染：

1. 将实例从服务中移除；
2. 保留源代码/镜像/模型哈希和最少量的脱敏日志；
3. 不要在特权环境中再次加载模型；
4. 轮换进程可访问的凭据；
5. 从已验证的不可变产物替换；
6. 如果不安全的 pickle 加载可能执行过代码，则重建镜像/主机；
7. 检查所有可写挂载中是否存在非预期修改。

全局 `weights_only=False` 补丁使模型加载成为代码执行边界，而不只是模型质量问题。

### 10.4 证书隐私或 OCR 事件

如果怀疑证书载荷暴露、陈旧工作、存储完整性失败或 OCR 身份漂移：

1. 停止新的证书准入，不要尝试 fallback processor；
2. 执行 EndCapture 或终止所属安全会话，并要求完成 DEK 销毁/清理屏障；无法证明清理时隔离该进程；
3. 只保留不含载荷的 reason code、release ID、版本、摘要、生命周期耗时和进程/容器证据；
4. 不要把 JPEG、OCR、提取、prompt、能力、token、socket 载荷或私有存储记录复制到事件工单；
5. 只使用上一套获批不可变包替换 OCR 镜像/模型/锁/清单，并重新检查 peer、无网络和无 GPU；
6. 撤销受影响的 OIDC/会话权威并重启唯一所属进程；
7. 如果 M7 回复在 End 清理得到证明前发出，或出现第二次个性化尝试，应按安全事件处理。

## 11. 故障排查矩阵

### 11.1 安装与启动

| 症状 | 可能原因 | 证据/检查 | 操作 |
|---|---|---|---|
| `requires-python` 失败 | 主机 Python 不是 3.11.7–3.11.x | `.venv/bin/python --version` | 使用受支持的 3.11 重建 venv |
| 处理程序依赖编译失败 | CUDA/编译器/RAM 不匹配，尤其是 `flash-attn` | 完整安装日志、`nvcc --version`、RAM | 使用受支持的工具链；保留第一条失败命令 |
| `Module ... not found in search path` | 错误的模块路径或搜索路径 | 配置 + 目标 `.py` | 修正部署配置；启动前验证 |
| 安装程序试运行通过，但启动时 YAML 加载失败 | 不同解析器的行为不一致 | 使用实际加载器验证 | 修复重复键或无效键；不要只依赖安装程序 |
| Qwen 预设 `DuplicateKeyError` | 两个 `connection_ttl` 条目 | 配置第 17/19 行 | 移除一个值并重新验证 |
| 进程以更少的处理程序启动 | 通用配置验证错误已被记录/跳过 | 在启动输出中搜索 `Registered handler` | 与已批准的处理程序列表比较；使部署失败 |
| 启动日志报错，但退出码仍为 0 | 未处理的启动路径在强制退出前保留默认 `exit_code=0` | 使用已知无效配置复现；检查就绪状态和日志 | 视为失败；在所有路径保留真实状态前，临时使用 `Restart=always` |
| `api_key`/401/403 | 缺失/错误的密钥或提供商模型授权 | 环境是否存在、提供商响应 | 注入正确密钥；绝不打印它 |
| 启动停滞或开始下载 | SenseVoice、数字人处理程序或第三方组件自动下载 | 网络、进程和文件活动 | 预置已验证产物；完成演练后阻止运行时出站流量 |

### 11.2 模型与数字人资源

| 症状 | 可能原因 | 操作 |
|---|---|---|
| LiteAvatar 首个会话失败 | 权重存在，但目标数字人资源不存在 | 运行 `download_avatar_model.py --model <avatar_name>` 并验证解压结果 |
| Smart Turn “model not found” | 任意 ONNX 使下载程序跳过，但精确的 `smart-turn-v3.1-cpu.onnx` 缺失 | 验证精确配置的文件名和摘要 |
| MuseTalk 源视频缺失 | `standard` 和 `duplex` 预设使用不同的源路径 | 验证主机和容器内的 `avatar_video_path` |
| MuseTalk 缓存错误 | S3FD 目录/检查点缺失或挂载错误 | 检查主机路径和容器 `/root/.cache/torch/hub/checkpoints` |
| FlashHead 导入/构建失败 | `flash-attn`、xformers、CUDA 或模型文件缺失 | 验证依赖构建和两个模型目录 |
| 模型加载使用了不安全模式 | 全局 `torch.load` 补丁 | 不要加载未验证产物；生产前修复 |
| 下载程序称完成但运行时失败 | 接受了部分目录 | 比较精确文件/大小/哈希；原子地重新获取 |

### 11.3 浏览器、TLS、RTC 与 TURN

| 症状 | 可能原因 | 操作 |
|---|---|---|
| 相机/麦克风 API 不可用 | 非 localhost HTTP 或权限被阻止 | 使用受信任 HTTPS；检查浏览器权限/策略 |
| HTTPS URL 被拒绝或返回 HTTP | 证书/密钥缺失，服务回退到明文 | 确认日志明确包含 `SSL enabled`，并检查监听协议 |
| 证书警告 | 自签名/不受信任、主机名/SAN 不匹配、到期 | 安装受信任且主机名有效的证书 |
| “Waiting…” 永远持续 | ICE/NAT/TURN 失败或应用未公布 TURN | 检查初始化配置和浏览器 ICE 候选项 |
| TURN UDP 可用但受限网络失败 | TCP/TLS 监听器/防火墙/cert 缺失 | 测试 `3478/tcp` 和 `5349/tls`；修复实际密钥挂载 |
| coturn 运行但没有中继候选项 | 没有 `RtcClient.turn_config`、凭据无效、外部 IP 错误 | 添加/验证配置并检查 coturn 日志 |
| TURN TLS 无法加载密钥 | Compose 将 `.crt` 挂载为密钥 | 只读挂载实际私钥 |
| TURN 中继滥用/带宽突增 | 公开静态凭据/默认配置 | 撤销/轮换、限制防火墙/对等方、启用配额 |
| 音频/视频漂移 | RTC FPS 与数字人 FPS 不同 | 把两者设为相同值，并运行长时间同步测试 |
| MuseTalk 在 FPS 警告后加载失败 | FPS 已自动校正，但 RTC 仍使用原始值 | 使用 24,000 的除数 FPS，并明确设置两个配置 |
| 媒体停滞/内存上升 | 无界跨线程 RTC 队列、慢客户端 | 终止会话，降低并发；修复队列设计 |
| 会话在 15 分钟后结束 | 默认 `connection_ttl: 900` | 按需修改，并重新测试资源清理 |

### 11.4 Docker 与 Compose

| 症状 | 可能原因 | 操作 |
|---|---|---|
| Docker CLI 可用，但无法连接守护进程 | Socket 权限或服务状态异常 | 使用经过批准的 Docker 访问方式；不要开启权限过宽的 root shell |
| 容器中 GPU 不可用 | NVIDIA 运行时未配置/授权 | 测试最小 CUDA 镜像和运行时配置 |
| 自定义镜像标签未生效 | 运行脚本写死了 `latest` | 显式指定要运行的镜像，或先重新标记 |
| `-p` 看似被忽略 | 辅助程序使用主机网络 | 在 Linux 上符合预期；直接绑定/防火墙主机端口 |
| Compose 配置检查通过，但启动失败 | 绑定挂载源缺失，或缺失路径被自动创建为目录 | 执行 `up` 前验证每个主机路径及其类型 |
| 镜像构建成功，但处理程序因 YAML 缺失而导入失败 | `.dockerignore` 移除了 `src` 下所有 `*.yaml`/`*.yml` | 缩小忽略规则或重新纳入必要文件，重建后检查目标运行时资源 |
| 构建脚本执行了非预期 shell 命令 | 不受信任的 `--tag` 被传入 `eval` | 保留调用和构建日志；停止构建；移除 `eval`；验证输入；轮换受影响的构建与镜像仓库凭据 |
| 应用可用，但 TURN 不可用 | Compose 启动顺序不代表服务健康或就绪，且应用缺少 `turn_config` | 添加健康检查，并明确向客户端下发 TURN 配置 |
| Agent 预设在镜像中导入失败 | 依赖层遗漏 Agent 的 `pyproject.toml` | Beta 功能暂时只使用原生部署；修复依赖后再重建 |
| Agent 预设在 Compose 中不可访问 | 预设绑定 8283，但 Compose 映射 8282:8282 | 明确修改端口映射和入口配置；仅限 Beta 功能 |

### 11.5 Manager 与隐私

| 症状 | 原因/操作 |
|---|---|
| Manager 令牌似乎无论何值都被接受 | 只在传统/默认兼容模式下符合预期；该模式应隔离/禁用 Manager。启用模式需验证 `oac:manager` 和票据准入，若仍接受则属于安全事件 |
| 未知客户端可见所有会话 | 传统/默认模式仍是未认证 Hub；启用模式出现此现象属于安全事件 |
| 配置快照泄漏密钥 | 内联处理程序密钥被序列化；轮换密钥并移除内联值 |
| 临时媒体持续增长 | 没有自动文件清理；停止暴露，建立安全的保留清理 |
| 日志包含完整转录内容 | 当前 INFO 日志；限制访问并修改/脱敏日志 |

### 11.6 安全证书采集与 OCR

当前公共采集路径会在 `PROCESSOR_NOT_READY` 停止，不能产生模板或释放结果。
下表中的模板/释放条目描述 owner-only 组件诊断和未来生产组合必须具备的行为，并非当前 HTTP 响应。
[录取通知书字段提取模块参考](certificate-extractor.md)记录了 `AdmissionNoticeExtractionFailureReasonV1` 原因码与字段级弃答契约。

| 症状/reason | 可能原因 | 操作 |
|---|---|---|
| 启用模式启动时报 `TLS_*` 或 `MULTI_WORKER_UNSUPPORTED` | TLS 材料缺失/不匹配/加密，或 worker 数不精确等于一 | 修正经过审查的 TLS 路径和 `workers`/`WEB_CONCURRENCY`；不得绕过门禁 |
| `AUTHENTICATION_FAILED` 或 `REQUIRED_SCOPE_MISSING` | `at+jwt` 无效，issuer/audience/时间/密钥不匹配，或用途 scope 错误 | 修复身份提供商/客户端流程；保持 `certificate:capture` 与 `oac:manager` 分离 |
| `UNSUPPORTED_PROFILE` | 客户端未请求精确 `hbtc_admission_notice_v1` | 修复客户端；不要增加动态 profile，也不要信任客户端提供的学校 |
| `PROCESSOR_NOT_READY` | 当前生产 Seal 尚未与 M6A OCR/M6B 提取组合，并且只允许构造器注入的测试 processor；通过帧门禁后无条件出现 | EndCapture 并清理浏览器状态；实现/审查生产组合并完成真实隔离 CPU 资格验证后再启用 |
| 日志警告 `CERTIFICATE_OCR_UNAVAILABLE_V1` | 启动部署候选格式错误、冲突或被拒绝；它不是 HTTP 采集 reason | 只比较获批哈希/身份/UDS 策略；不得启用 fallback、下载或网络；有效候选仍不能让当前 Seal 处理 |
| `NEEDS_RECAPTURE` | 当前实现收到的独立 JPEG 少于三张 | 在上限内增加新序号；已满时先 End，再开始新采集 |
| 模板为 `NOT_MATCHED` 或 `INSUFFICIENT` | 学校标题不匹配，或兼容标题/正文锚点不足 | 不得提取、释放、猜测或声称真实性；仅在 UX 允许时重新拍摄 |
| `ADMISSION_RELEASE_NO_FIELDS` | 没有提取字段的状态精确为 `FOUND` | 不启动个性化回合并结束；不得释放歧义/缺失候选 |
| 采集停留在 `FAILED_CLOSED` | 清理、权威、身份、超时或陈旧工作证明失败 | 终止/隔离安全会话；仅使用不含载荷的证据调查 |
| 取消/错误/End 后浏览器仍保留相机/照片状态 | M8 清理或相机让渡失败 | 按隐私缺陷处理；撤销 Object URL、停止采集轨道、恢复普通轨道并清空内存能力 |

## 12. 本次审查的验证记录

所有命令都限制了执行范围，并避免下载模型、调用付费 API、启动服务或产生持久的外部影响。

### 12.1 审查环境

| 工具 | 观察结果 |
|---|---|
| 主机 Python | 3.14.4；项目不支持 |
| 项目 venv Python | 3.11.16；满足项目约束 |
| uv | 0.12.5 |
| Docker CLI | 29.1.3 |
| Docker Compose | 2.40.3 |
| Node | 26.2.0 |
| npm | 12.0.1 |
| Bash | 5.3.9 |
| FFmpeg | 8.0.1 |
| GPU 查询 | 不可用：审查环境阻止访问 NVML |
| Docker 守护进程 | 当前用户不可用：访问 socket 时权限被拒绝 |

工具版本描述的是此审查主机，而不是项目最低要求。

### 12.2 成功的检查

| 检查 | 结果 | 含义 |
|---|---|---|
| 使用隔离缓存执行 `uv lock --check --offline` | 退出码 0；149 个包 | 本地存在但被 Git 忽略的锁文件在离线状态下保持最新；它不能作为受版本控制的交付证据 |
| 对每个预设执行 `install.py --dry-run` | 13/13 的退出码均为 0 | 无需实际安装即可完成依赖发现 |
| 真实 Dynaconf/Pydantic 加载器 | 12/13 有效 | Qwen 预设因重复键被拒绝 |
| 缺失配置的进程探针 | 记录配置缺失，并以退出码 `0` 结束 | 确认当前进程退出码会掩盖启动失败 |
| 已启用模块路径扫描 | 105 个引用，0 个缺失路径 | 每个已启用模块字符串都映射到源文件 |
| Python 源代码编译 | 910 个 `src/**/*.py`，0 个语法失败 | 仅进行了大范围语法检查；其中包括外部代码树 |
| 第一方 Python AST 扫描 | 255 个文件，0 个语法失败 | 仅第一方语法 |
| `docker compose config --no-interpolate` | 退出码 0 | 只验证 Compose 结构和规范化结果 |
| 受支持的顶层 shell 脚本 `bash -n` | 退出码 0 | 只验证 shell 语法 |
| 将 MuseTalk FFmpeg 辅助程序作为脚本运行 | 退出码 0 | 可以正确找到 FFmpeg 可执行文件 |
| 模型下载程序 `--help` | 退出码 0 | CLI 可以加载；不支持 `dry-run` |

一个第三方 Python 文件对 `is not -2` 发出了警告；它并未使编译失败。

### 12.3 已复现的失败

#### Qwen 配置的实际加载

使用实际加载器加载 `config/chat_with_qwen_omni.yaml` 时，会因 `connection_ttl` 被声明两次而抛出 `DuplicateKeyError`。
安装程序的试运行仍会通过，因此该问题会直接阻止部署。

#### 进程失败状态

```bash
.venv/bin/python -B src/demo.py \
  --config /tmp/openavatarchat-review-missing-config.yaml
```

进程记录配置不存在并返回退出码 `0`。
这确认该未处理启动路径会在调用 `os._exit(exit_code)` 前保留默认退出码。
没有创建文件，也没有启动服务。

#### MuseTalk 单项 pytest

```bash
.venv/bin/pytest -q \
  src/handlers/avatar/musetalk/MuseTalk/test_ffmpeg.py
```

退出码为 1：测试函数请求了未定义的 `ffmpeg_path` fixture。
同一个辅助程序按预期方式直接作为脚本运行时能够成功，因此这是第三方 pytest 收集缺陷，并不能证明 FFmpeg 不可用。

#### 2026-08-18 预构建前端类型检查

前端子模块的 Node 和 Web 类型检查均以退出码 2 结束：

- main/preload 代码中存在未使用符号和缺失的 `Window` 属性；
- `gaussian-splat-renderer-for-lam` 的 TypeScript 模块类型无法解析。

正常的后端部署会提供已检入的预构建 `dist`。
这些错误意味着无法声明前端可以从零干净重建并通过类型检查，但不能据此断定现有 `dist` 无法提供服务。

#### 审查主机上的 pnpm

前端声明的包管理器版本为 pnpm 10.10.0。
在审查主机的 Node 26/Corepack 组合下，执行 `pnpm --version` 会报 `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`。
应在干净的构建环境中使用该前端项目支持的 Node/Corepack 工具链。

#### Compose 就绪状态

Compose 语法检查通过，但预期的绑定挂载源不存在，TURN 私钥挂载也有误。
本次没有运行 `docker compose up`，因为它可能创建目录、启动持久服务、拉取镜像，并公开主机网络端口，而无法产生有意义的就绪部署。

### 12.4 本次未执行的检查

- 完整应用启动；
- 模型和依赖下载；
- 付费/外部 API 调用；
- Docker 镜像构建或 Compose 启动；
- 真实 TLS/TURN/浏览器 WebRTC；
- 宽泛的供应商 pytest 收集；
- 文档构建输出；
- 性能/负载/GPU 内存测量。

不应从静态/语法检查推断任何端到端成功、生产就绪状态或性能结果。

### 12.5 安全采集增量证据

2026-08-27 的刷新还复核了当前 HEAD `6db2b96`、固定的 WebUI `b82f290`、启用/禁用路由差异、M2/M3 权威与围栏、M4/M5 采集/私有存储、M6A–M6C OCR/提取/模板、M7 释放、M8 WebUI 文档/测试和 OCR Compose 边界。
上述各层现已拥有第一方专项测试。
复核还确认生产 Seal 不会调用任何 M6A/M6B/M7 owner-only seam，并无条件要求构造器注入的测试 processor；该组合缺口与 OCR 资格验证是两个独立的发布阻断项。

| 本次刷新重新执行的检查 | 结果 | 范围 |
|---|---|---|
| M6B 提取器套件 | 75 passed，3.32 s；一条第三方弃用警告 | 四字段契约/规则、歧义、页面顺序不变性、加密存储、权威/生命周期、隔离、竞争和性能冒烟 |
| M6C 模板套件 | 74 passed，1.19 s | 固定 HBTC 身份、标题/正文兼容性、对抗布局、仅匹配页面提取和性能冒烟 |
| M7 后端套件 | 40 passed，1.01 s | 释放契约、净化器、权威/生命周期、竞争、ChatAgent 上下文/工具和性能冒烟 |
| 证书启动门禁服务套件 | 35 passed，3.34 s；一条第三方弃用警告 | 启用/禁用配置、TLS/worker/启动行为 |
| 使用 Pydantic 验证文档中的安全 service 配置 | 通过 | 确认 YAML 结构和精确 `certificate:capture` 字段契约 |
| `docker compose --profile certificate-ocr config --no-interpolate --quiet` | 通过 | 仅渲染 Compose；未构建镜像或启动服务 |
| 双语文档门禁 | 通过：5 对文档、每种语言 59 个相同 fenced block、35 个匹配表格、116 个本地链接 | 结构/内容对齐和本地目标存在性 |
| 前端 `pnpm run test:m8` | 未执行 | 固定子模块没有 `node_modules`；Node 26/Corepack 以 `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING` 无法启动 pnpm；未尝试安装 |

本次没有使用真实 Paddle/PP-OCRv6 模型、合格 sidecar 镜像、生产清单、真实证书、浏览器相机、网络服务或 GPU。
不得把合成测试成功提升为生产 OCR 或端到端成功声明。

## 13. 建议的验证流水线

### 阶段 A — 源代码与配置

- 干净的源代码检出和预期的子模块提交；
- 密钥扫描；
- 对每个受支持预设进行真实加载器验证；
- 拒绝重复 YAML 键；
- 已启用模块/路径验证；
- 启用/禁用路由清单及用途 scope 隔离；
- 第一方 lint/type/unit 测试；
- 依赖锁/约束验证。

### 阶段 B — 构建产物

- 从固定的基础摘要进行干净且具备离线能力的镜像构建；
- SBOM 和来源证明；
- 漏洞/许可证策略；
- 以非 root 用户运行；
- 具有哈希和许可证的精确模型清单；
- 单独锁定/哈希的 CPU OCR 镜像、模型、身份、资格验证记录、部署清单和 UDS 所有权策略；
- 前端干净安装/构建/类型检查。

### 阶段 C — 组件集成

- 模拟和真实的选定处理程序图；
- 模型初始化；
- 云处理程序身份验证/错误/超时；
- `standard` 与 `duplex` 数据流和取消测试；
- 会话隔离和清理；
- 分别运行里程碑安全/围栏/采集/OCR/提取/释放测试，包括陈旧回调和清理竞争；
- 不使用构造器注入测试 processor，由生产 Seal 调用受精确围栏保护的 OCR、提取、释放、失败和清理路径的集成测试；
- 带活动会话的 SIGTERM；
- Manager 授权和保留。

### 阶段 D — 媒体与网络

- 浏览器 HTTPS 权限；
- M8 相机让渡、有界 JPEG 处理、取消/错误/End 清理和真实文档采集；
- RTC 信令和音频/视频/文本；
- FPS 和长时间 A/V 同步；
- 网络丢失/重连；
- 慢客户端背压；
- 外部 TURN UDP/TCP/TLS 中继；
- 凭据到期和中继滥用控制。

### 阶段 E — 容量与发布

- 目标并发浸泡；
- GPU/RAM/CPU/磁盘/网络安全余量；
- 在生产组合存在后，执行真实 CPU OCR 统计资格验证、RSS/线程/进程/延迟预算、无 GPU/无网络证明，以及与实时 GPU 工作负载的争用；
- p50/p95/p99 延迟；
- 外部 API 速率/支出；
- 金丝雀、告警、备份/恢复和回滚演练。

只有当每个阶段都有明确负责人、证据产物和验收结论时，才能发布。

## 14. 建议修复顺序

1. 阻止直接公开访问；强制经身份验证的入口，并在传统模式中禁用/保护 Manager，或验证严格的启用模式授权。
2. 移除已检入的 TURN 凭据；修正 TURN 私钥、配置及应用侧连接方式。
3. 移除或隔离不安全的 PyTorch 加载，并验证不可变模型产物。
4. 为 RTC 输出实现容量受限、可安全跨线程使用的队列。
5. 建立已跟踪的锁定依赖项和不可变镜像/模型清单。
6. 在 TLS 或关键前置条件校验失败时阻止启动。
7. 修复 Qwen 配置、模型下载程序结果验证和 FPS 兼容性检查。
8. 在关闭/失败时以事务方式停止活动会话。
9. 保留真实进程失败状态并有序清理日志/资源。
10. 从特权镜像构建辅助程序中移除 `eval`。
11. 接入历史记录保留配置，或移除当前不起作用的调优说明。
12. 添加核心测试、指标、能感知前置条件的就绪检查，并改用非 root 用户运行。
13. 对齐版本控制和文档。
14. 只有当该功能成为部署优先事项时，再处理 Beta Agent 的打包和回调问题。
15. 在缺失的 Seal→OCR/提取/释放组合完成实现与独立审查，且单独 CPU OCR 资格验证和真实相机 M8 验收门禁通过前，保持生产证书处理关闭。
