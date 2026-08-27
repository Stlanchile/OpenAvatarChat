# OpenAvatarChat 技术文档

**语言：** 简体中文 · [English](../README.md)

本套文档基于当前检出版本的 OpenAvatarChat 源代码，面向需要评估、部署、加固、运维或扩展该服务的工程师，不仅限于运行快速入门示例。

## 审查快照

| 审查项 | 记录 |
|---|---|
| 审查日期 | 2026-08-27 |
| 分支 | `main` |
| 提交 | `6db2b96176afc9f324d022e01f96b3cf3d811699` |
| 应用内报告版本 | `0.6.0` |
| 根包版本 | `0.1.0` |
| 主要运行时 | Python 3.11、FastAPI/Uvicorn、FastRTC/WebRTC、PyTorch CUDA 12.8；可选的隔离式 CPU OCR sidecar |
| 部署方式 | 原生 `uv`、Docker、带 coturn 和集成/资格验证门控 OCR profile 的 Docker Compose |
| 审查依据 | 原始全项目审查，以及对 Secure Certificate Capture V1 里程碑 1–8 的源码增量复核 |

文中的源码引用和安全采集现状均以上述提交为基准；后续修改可能导致行号偏移。

部署指南引用的外部平台资料仍以 2026-08-18 的复核结果为准，仅用于说明前置条件；这不代表当前检出版本已在审查环境中通过端到端部署。

## 文档导航

- [技术报告](technical-report.md) — 介绍架构、执行模型、组件、数据流、状态、接口、配置、安全边界和 Secure Certificate Capture V1，并列出按优先级排序的审查发现。
- [录取通知书字段提取模块](certificate-extractor.md) — 说明 `AdmissionNoticeExtractorV1`、`HbtcAdmissionNoticeTemplateMatcherV1` 和 `PrivateAdmissionNoticeExtractionServiceV1` 的职责边界、四字段契约、固定模板规则、私有存储/围栏、失败结果和当前生产集成缺口。
- [部署指南](deployment-guide.md) — 帮助选择部署方式，说明前置条件、预设选择、原生安装、Docker、Compose/TURN、公网生产拓扑，以及受集成/资格验证门控的证书组件。
- [运维与验证](operations-validation.md) — 汇总健康检查、可观测性、容量规划、备份、升级、回滚、证书隐私与清理门禁、故障排除、验证证据与待确认事项。

部署内容按部署方式编排，相关依赖统一放在对应流程中说明。

## 结论概览

OpenAvatarChat 的核心是一条模块化、由配置驱动的实时媒体管线：

```text
Browser / LAM client
        |
        +--> RTC or WebSocket client handler
        |         |
        |         v
        |    VAD -> ASR -> LLM -> TTS -> avatar renderer
        |         |                         |
        |         +---- stream graph -------+
        |         +---- signals/history ----+
        |
        +--> Authenticated HTTPS admission-notice capture
                  |
                  v
             WorkFenceV1 -> encrypted evidence
                  |
                  +--> production Seal -> PROCESSOR_NOT_READY
                  |
                  +--> owner-only seams (not production-wired):
                       CPU OCR over private UDS -> fixed-template extraction
                       -> one sanitized ChatAgent turn after EndCapture
```

从源代码看，系统已经具备多项良好的运维基础：明确的处理程序契约、独立的会话上下文、显式的流祖先关系与取消机制、有界的流回收、健康检查端点、按预设发现依赖项，以及固定到具体提交的 Git 子模块。
可选的证书采集模式还增加了失败关闭的 TLS/OIDC 启动门禁、会话/传输/Manager 准入、代际围栏和采集级加密证据。
无网络 CPU OCR、确定性的固定模板提取和一次性净化释放已作为私有组件实现，并有隔离测试，但生产 Seal 路径不会调用它们。

不过，随附配置目前更适合作为开发或参考方案。
投入生产前，至少需要解决以下问题：

1. 证书采集默认关闭；在该传统/默认模式下，应用和 Manager 仍保留未认证行为。
   启用证书模式后虽会增加 OIDC 准入，但不会自动增加限流，也不意味着可以把 `8282`/`8283` 直接暴露到公网。
2. 已检入的 coturn 配置使用公开的静态凭据，且 Compose 文件将证书挂载为 TURN 私钥。
   在这种配置下，TURN-over-TLS 无法正常工作。
3. 在 Compose 中启动 coturn 并不会自动向浏览器提供 TURN 配置；仍需增加 `RtcClient.turn_config` 块。
4. 模型文件从可变的上游修订版本下载，且没有校验和；启动过程还在全局范围内允许不安全的 PyTorch pickle 反序列化。
5. 无法仅凭受版本控制的仓库复现依赖解析结果：`uv.lock` 被忽略，镜像构建既不复制也不强制使用它。
6. Qwen-Omni 预设在实际的 Dynaconf 加载流程中失败，因为 `connection_ttl` 被声明了两次。
7. `.dockerignore` 会从构建上下文中排除所有 `*.yaml`/`*.yml`，包括数字人和语音子模块使用的运行时 YAML 文件。
   标准镜像可以成功构建，却仍可能在处理程序启动时不完整。
8. 对于未被证书配置门禁显式捕获的启动失败，`src/demo.py` 仍会让 `exit_code` 保持为 `0`，再从 `finally` 调用 `os._exit(exit_code)`。
   因此，不能只凭进程退出码判断部署成功。
9. 录取通知书组件已实现到 M8 WebUI，但没有生产端到端连线：Seal 只允许构造器注入的测试 processor，不会调用私有 OCR 或提取服务。
   仓库也没有检入获批的 OCR 依赖锁、生产模型、推理身份或 CPU 资格验证记录。
   通过帧数门禁后，生产 Seal 因此会无条件返回 `PROCESSOR_NOT_READY`；模板匹配也不等于真实性验证。

证据与缓解措施详见[技术报告：按优先级排序的审查发现](technical-report.md#prioritized-findings)。

## 建议路径

- 首次进行受控部署时，建议在专用 Linux GPU 主机上使用原生 `uv` 流程，并选择标准的 LiteAvatar + 云端 TTS 预设。
- 如需隔离且可重复的运行环境，可在验证配置、模型、证书和 GPU 运行时后使用 Docker 镜像。
  当前镜像仍受浮动依赖解析影响，无法做到逐字节复现。
- 请将随附的 Compose/coturn 栈视为部署脚手架。
  离开可信实验环境前，必须完成部署指南中列出的全部 TURN 和 TLS 修正。
- 请将 `certificate-ocr` Compose profile 视为资格验证脚手架，而不是可直接运行的生产 OCR 服务。
  在生产 Seal 到 OCR/提取/释放的组合完成实现与审查，且配置好精确 CPU 产物、部署清单、UDS 所有权策略和验收证据前，不得启用成功证书处理。
- 面向局域网或公网用户时，应在带身份验证的反向代理处终止受信任 TLS，将应用保留在内部网络，并运行经过明确配置的 TURN 服务。
- 除非明确需要 Beta Agent 预设，否则应保持 OpenClaw 集成关闭。
  本报告只把它作为次要集成边界进行说明。

## 术语说明

为避免混淆，本套文档统一使用以下证据等级：

- **已确认** — 可由源代码或在当前检出版本中实际执行的命令直接证实。
- **有条件支持** — 已有相应代码，但能否成功运行仍取决于硬件、模型、凭据、网络服务或尚未执行的构建。
- **未验证** — 未进行端到端验证，因此不作成功声明。
- **审查发现** — 具有现实触发条件和实质影响的具体代码或部署问题；不代表已经发生利用或故障。

本次文档刷新只修改 `tech-doc/`；文中所述产品与 WebUI 里程碑提交在本次复核前已存在于检出版本中。
