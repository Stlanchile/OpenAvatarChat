# 录取通知书字段提取模块参考

**语言：** 简体中文 · [English](../certificate-extractor.md)

本文面向维护和审查 `src/certificate_capture/extraction/` 的工程师，说明录取通知书字段提取模块的职责边界、调用关系、数据契约、模板判定规则和失败关闭行为。
项目中有时会简称它为“证书提取器”，但当前实现并不是通用证书解析框架：它只处理服务端固定的湖北交通职业技术学院录取通知书模板，并且只输出四个经过保守判定的字段。

本文所述源码与行为以 2026-08-27 的审查提交 `6db2b96176afc9f324d022e01f96b3cf3d811699` 为概念基准。

## 1. 目的与当前状态

| 项目 | 当前状态 |
|---|---|
| 已实现范围 | `AdmissionNoticeExtractorV1` 的确定性四字段提取，以及 `HbtcAdmissionNoticeTemplateMatcherV1` 的单模板兼容性判定 |
| 输入 | 一至三份 `StoredOcrResultV1`；它们指向由 `PrivateOcrServiceV1` 写入的加密 `OcrPageResultV1` 记录，只有私有提取服务可以解密 |
| 输出 | 加密保存的 `AdmissionNoticeExtractionV1`，以及不包含字段明文的 `StoredAdmissionNoticeExtractionV1` 收据 |
| 生产状态 | 解析器、模板匹配器、私有服务和隔离测试均已实现；但 `CaptureCoordinatorV1._execute_seal_attempt_v1()` 尚未调用私有 OCR、提取或安全释放链路 |
| 公共 API | 无：没有 OCR、提取、模板匹配或字段结果的 HTTP/WebSocket 端点 |
| 信任声明 | `MATCHED` 只表示 OCR 文本和版面满足固定解析器的输入条件；不证明文档真实、有效、由学校签发，也不证明录取状态 |

当前 `CaptureCoordinatorV1._execute_seal_attempt_v1()` 只检查构造器注入的 `_test_processor_v1`，随后注册 `CAPTURE_MOCK_PROCESSOR` 并执行 `_run_mock_processor_v1()`。
生产请求通过唯一帧数量检查后仍会返回 `PROCESSOR_NOT_READY`；
即使 OCR 部署清单有效、UDS sidecar 健康，也不会进入 `_process_private_ocr_frames_v1()` 或 `_process_private_admission_notice_extraction_v1()`。
因此，本文描述的是已经实现并经过组件级验证的私有模块，而不是已经接通的生产文档处理功能。

## 2. 三种不同的模块角色

以下名称彼此相关，但不能混用：

| 名称 | 职责 | 不负责 |
|---|---|---|
| `AdmissionNoticeExtractorV1` | 纯确定性解析器；`match_pages_v1()` 执行模板判定，`extract_pages_v1()` 只对单页已匹配的 `OcrPageResultV1` 提取字段并进行跨页聚合 | 解密证据、申请工作权限、写入存储或验证文档真实性 |
| `HbtcAdmissionNoticeTemplateMatcherV1` | 固定模板兼容性判定器；`match_and_select_pages_v1()` 同时给出页面集合结果和允许进入字段提取的页面 | 提取语义字段、判断签发方或验证真实性 |
| `PrivateAdmissionNoticeExtractionServiceV1` | 仅供 `CaptureCoordinatorV1` 构造和调用的私有编排服务；`extract_v1()` 负责围栏校验、解密、调用解析器、加密写回和返回收据 | 向普通处理程序、插件、路由或浏览器暴露明文 |

`certificate_capture.extraction` 的公开导出清单包含纯解析器、模板匹配器、`AdmissionNoticeTemplateCompatibilityErrorV1` 和固定规则身份，但不包含私有编排服务。
该服务由 `CaptureCoordinatorV1` 直接导入，构造时还必须携带模块内部的 `_EXTRACTION_SERVICE_CONSTRUCTION_AUTHORITY_V1`；普通调用方无法按常规方式实例化它。

## 3. 包与契约导航

| 源码 | 作用 |
|---|---|
| [`extraction/admission_notice.py`](../../src/certificate_capture/extraction/admission_notice.py) | 定义 `_name_candidates_v1()`、`_province_candidates_v1()`、`_college_candidates_v1()`、`_major_candidates_v1()`、`_aggregate_field_v1()` 和 `AdmissionNoticeExtractorV1` |
| [`extraction/hbtc_admission_notice.py`](../../src/certificate_capture/extraction/hbtc_admission_notice.py) | 定义 `_match_page_v1()`、`ordered_admission_notice_pages_v1()` 和 `HbtcAdmissionNoticeTemplateMatcherV1`，负责标题/正文兼容性判定和匹配页面筛选 |
| [`extraction/reading_order.py`](../../src/certificate_capture/extraction/reading_order.py) | `reconstruct_reading_order_v1()` 按归一化坐标重建可视行；`forward_run_paths_v1()` 生成有界的相邻文本路径 |
| [`extraction/normalization.py`](../../src/certificate_capture/extraction/normalization.py) | 提供封闭的空白折叠、锚点标点规范化、结构字符修剪、Unicode 控制字符拒绝和汉字判断规则 |
| [`extraction/identity.py`](../../src/certificate_capture/extraction/identity.py) | 构造 `DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1`，将提取器、模板、匹配规则、字段规则和归一化版本绑定为一个可哈希身份 |
| [`extraction/service.py`](../../src/certificate_capture/extraction/service.py) | `PrivateAdmissionNoticeExtractionServiceV1.extract_v1()` 串联授权、工作围栏、加密存储、幂等复用、取消和稳定错误原因码 |
| [`contracts/admission_notice.py`](../../src/certificate_capture/contracts/admission_notice.py) | 定义不可变字段/结果契约、canonical JSON 解析、摘要、存储键和不透明收据 |
| [`contracts/admission_notice_template.py`](../../src/certificate_capture/contracts/admission_notice_template.py) | 定义唯一模板描述符、锚点 ID、`AdmissionNoticeTemplateMatchStatusV1` 和 `AdmissionNoticeTemplateMatchV1` |
| [`coordinator.py`](../../src/certificate_capture/coordinator.py) | 创建私有服务，并通过 `_process_private_admission_notice_extraction_v1()` 控制提取与安全释放暂存 |

## 4. 私有数据流

```text
StoredOcrResultV1 receipts (1..3)
  -> PrivateAdmissionNoticeExtractionServiceV1.extract_v1
  -> exact live OCR_INFERENCE parent
  -> ADMISSION_NOTICE_EXTRACTION child work
  -> decrypt OcrPageResultV1 records
  -> deterministic reading-order reconstruction
  -> HbtcAdmissionNoticeTemplateMatcherV1.match_and_select_pages_v1
  -> matched pages only
  -> AdmissionNoticeExtractorV1.extract_pages_v1
  -> canonical AdmissionNoticeExtractionV1
  -> PrivateEvidenceStoreV1.put_admission_notice_extraction_v1
  -> StoredAdmissionNoticeExtractionV1 receipt
  -> optional AdmissionNoticeSafeReleaseServiceV1.stage_extraction_v1
```

`PrivateAdmissionNoticeExtractionServiceV1.extract_v1()` 接收一至三份互不重复的 `StoredOcrResultV1`。
它先通过 `_register_extraction_child_v1()`，把 `ADMISSION_NOTICE_EXTRACTION` 注册为存活 `OCR_INFERENCE` 的精确子工作；
如果父工作种类、会话代次、截止时间或捕获状态不匹配，请求会以 `EXTRACTION_STALE` 失败。

随后，每份 OCR 收据都在独立的 `CAPTURE_EVIDENCE_READ` 子工作中交给 `PrivateEvidenceStoreV1.get_ocr_result_v1()` 解密。
服务会在私有存储读取前、解密返回后、开始字段提取前、提取返回后、写入内存前、写入私有存储前以及返回收据前，分别调用 `_require_live_v1()` 检查 `CaptureEpochV1`、私有授权对象和 `WorkFenceV1`。
任何阶段失去授权或跨代次执行，都会停止后续处理，不会把陈旧结果写入新一轮采集。

`AdmissionNoticeExtractorV1.extract_pages_v1()` 接收不可变的 `OcrPageResultV1` 元组。
`ordered_admission_notice_pages_v1()` 要求所有页面引用同一个 `CaptureEpochV1` 实例，并拒绝重复的 OCR 结果 ID、帧 ID 或 `OcrSpanV1.span_id`。
页面按结果 UUID 排序，因此调用方传入顺序、相机拍摄顺序和帧序号都不能影响判定结果。

`HbtcAdmissionNoticeTemplateMatcherV1.match_and_select_pages_v1()` 只把单页结果为 `MATCHED` 的页面交给字段提取。
最终 `AdmissionNoticeExtractionV1` 仍记录本次输入的全部 OCR 结果 ID 和帧 ID，使密文绑定到完整输入集合；
但 `INSUFFICIENT` 页面不能提供字段，也不能从另一页借用学校标题或正文锚点来拼成一次匹配。

## 5. 输出契约

`AdmissionNoticeExtractorV1.extract_pages_v1()` 的明文结果只在私有调用栈中短暂存在，随后由 `PrivateEvidenceStoreV1.put_admission_notice_extraction_v1()` 立即编码为 `canonical JSON` 并加密。
其逻辑结构固定如下：

```text
AdmissionNoticeExtractionV1 {
  schema_version
  capture_epoch
  source_ocr_result_ids[1..3]
  source_frame_ids[1..3]
  extraction_identity
  name
  source_province
  college
  major
}

ExtractedAdmissionFieldV1 {
  schema_version
  status: FOUND | AMBIGUOUS | NOT_FOUND
  value?
  source_span_ids[]
  source_polygon?
}
```

语义字段严格限定为四个。
学校名称由 `HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1` 在服务端固定保存，不是第五个 OCR 字段，也不能由客户端、OCR 文本或模板页面覆盖。

| 字段 | 契约上限 | 当前确定性规则 |
|---|---:|---|
| `name` | 32 个码点 | `_name_candidates_v1()` 只读取 `同学` 前、结构上独立的称呼；通常为 2–4 个汉字，含间隔点时最多 8 个字符 |
| `source_province` | 16 个码点 | `_province_candidates_v1()` 要求候选完整落在 `经…高等学校招生委员会…批准` 句式内，并精确命中封闭的省级名称表 |
| `college` | 128 个码点 | `_college_candidates_v1()` 还将当前解析长度限制为 64 个字符，要求它位于 `你被录取到我校` 之后，并以受支持的教学单位后缀结束 |
| `major` | 256 个码点 | `_major_candidates_v1()` 要求专业名称紧接在 `专业学习` 之前，字符和标点位于封闭集合内，且中英文括号必须配对 |

候选值会拒绝 Unicode 控制字符、格式控制字符、代理项和私用区字符。
`normalize_candidate_whitespace_v1()` 只折叠布局空白并修剪明确允许的外围结构标点；`canonical_anchor_text_v1()` 只删除锚点中的布局空白，并规范少量全角/半角结构标点。
模块不会进行模糊匹配、拼写修正、字典补全、NFKC 改写、LLM/VLM 推理或网络查询，因此规则相同、输入相同就会得到相同结果。

### 5.1 字段级弃答

| 状态 | 含义与保留内容 |
|---|---|
| `FOUND` | `_decision_from_candidates_v1()` 在单页只发现一个候选，且 `_aggregate_field_v1()` 确认所有已找到值一致。记录保留字段值和 1–32 个排序后的 `source_span_ids`；能够表示为单一矩形时才保留 `source_polygon`。 |
| `AMBIGUOUS` | 单页出现多个候选、不同匹配页面给出不同值、任一页面已判为歧义，或合并后的 `source_span_ids` 超出上限。该字段必须清空值、`source_span_ids` 和 `source_polygon`。 |
| `NOT_FOUND` | 所有匹配页面都没有提供合法候选。该字段必须清空值、`source_span_ids` 和 `source_polygon`。 |

`_aggregate_field_v1()` 对四个字段分别执行聚合：任一匹配页面出现 `AMBIGUOUS`，该字段的最终结果就保持 `AMBIGUOUS`；多个页面只有在非空值完全一致时才能得到 `FOUND`。
某个页面的 `NOT_FOUND` 不会否定另一页唯一且一致的 `FOUND`，某个字段缺失也不会让其他字段失效。
模块始终选择弃答，而不会按置信度、页面顺序、帧顺序或 OCR 分数强行挑选候选。

对于语义字段候选，`_scores_qualify_v1()` 会检查字段值及其局部锚点涉及的 `OcrSpanV1.raw_engine_score`：只要某个已提供分数低于 `0.50`，该候选就被丢弃；
`raw_engine_score is None` 则不会单独造成拒绝。
这个数值只用于字段候选过滤，不参与 `HbtcAdmissionNoticeTemplateMatcherV1` 的模板判定，也不是经过校准的概率、文档真实性分数或学校签发置信度。

### 5.2 规范形式、身份与复用

`AdmissionNoticeExtractionV1` 是不可变 dataclass，`canonical_json_v1()` 的输出上限为 16 KiB。
`admission_notice_extraction_from_canonical_json_v1()` 会执行严格反序列化：拒绝未知或缺失字段、重复 JSON 键、无效 UTF-8、非 canonical 编码、过深嵌套、无效 UUIDv7、不匹配的 `CaptureEpochV1`、非法的状态/值组合，以及超过计数或长度上限的溯源信息。
`FOUND` 必须至少带一个 `source_span_id`；`AMBIGUOUS` 和 `NOT_FOUND` 则不得携带任何可回答内容。

`DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1` 将会影响结果语义的各项规则绑定在一起：

- `extractor_id`：`admission-notice-extractor.v1`；
- `template_id`：`hbtc_admission_notice_v1`；
- `template_match_rule_version`：`hbtc-admission-notice-template-match.v1`；
- `rule_set_version`：`admission-notice-rules.v2`；
- `normalization_version`：`admission-notice-normalization.v1`。

当前采用 V2，是因为省份候选所依赖的必需锚点 `批准` 现在也纳入
`raw_engine_score` 权威范围。V1 常量只用于标识历史记录；当前固定提取器
会拒绝与其实际规则不完全一致的调用方自定义身份，避免用旧版本号标注新行为。

`AdmissionNoticeExtractionStorageKeyV1` 由排序后的 OCR 结果 ID 元组和 `extraction_identity_sha256` 组成。
`PrivateEvidenceStoreV1.find_admission_notice_extraction_v1()` 会先查找完全相同的键；命中后直接返回 `reused=True` 的既有加密收据，不会再次运行字段解析。
因此，只要模板判定、字段语法、归一化或输出语义发生变化，就必须升级对应的版本字符串并补充复用测试；否则旧密文可能被误认为新规则生成的结果。

## 6. HBTC 模板兼容性门禁

V1 只包含一个不可变、由服务端持有的模板：

| 项目 | 精确值 |
|---|---|
| 模板 ID | `hbtc_admission_notice_v1` |
| 可信学校 | `湖北交通职业技术学院` |
| 提取器 ID | `admission-notice-extractor.v1` |
| 匹配规则版本 | `hbtc-admission-notice-template-match.v1` |

`BeginCapture.profile_id` 只接受这一模板 ID，并最终写入 `CaptureSetV1.profile_id`。
`PrivateEvidenceStoreV1.put_admission_notice_extraction_v1()` 还会再次比较该值与 `AdmissionNoticeExtractionIdentityV1.template_id`。
当前实现不提供运行时模板注册表、通用多校插件、客户端指定学校、从 OCR 文本推导学校身份或通过网络查询模板的能力。

### 6.1 所需证据

`_match_page_v1()` 首先调用 `reconstruct_reading_order_v1()` 重建版面，再要求页面上方标题区域能够精确还原 `湖北交通职业技术学院`。
同一标题可以被 OCR 拆成同一行的多个 `OcrSpanV1`，也可以分布在两条几何相关的相邻标题行；但如果标题带有会改变学校身份的嵌套修饰词，或出现实质不同的学校名称形态，该页会被视为冲突。

除标题外，以下四个正文锚点中至少三个必须满足有界区域、局部语法、几何关系和合理阅读顺序：

| 锚点 ID | 文本 |
|---|---|
| `student-salutation` | `同学` |
| `admission-committee` | `高等学校招生委员会` |
| `admission-body` | `你被录取到我校` |
| `major-study` | `专业学习` |

`_body_signature_v1()` 要求符合条件的正文锚点起始于至少三条不同的重建可视行，因此把若干提示语挤在一两行中不能伪造完整正文结构。
页脚中的重复文字不能独立满足正文特征。
相邻锚点还必须保持合理的水平重叠；唯一例外是 `admission-body` 到 `major-study` 的转换，其归一化水平间距不得超过 `0.18`。
重复上传内容相同的页面不会增加模板判定权重。

### 6.2 页面集合结果

| 结果 | 页面集合行为 |
|---|---|
| `MATCHED` | 至少一页单独具备精确学校标题和足够的正文结构，且没有任何页面出现冲突学校标题。`match_and_select_pages_v1()` 只返回这些单页已匹配页面供字段提取。 |
| `NOT_MATCHED` | 任一页面出现实质不同的学校标题。该结果优先于其他页面的 `MATCHED` 或 `INSUFFICIENT`，并在字段提取前终止。 |
| `INSUFFICIENT` | 没有发现冲突学校，但也没有任何一页能独立提供足够的标题与正文证据；同样不会产生可回答字段。 |

`AdmissionNoticeTemplateMatchV1` 的 docstring 明确把 `MATCHED` 定义为“解析兼容性决定”。
界面、日志、客服说明和模型提示词都不得把它改写成“文档真实”“学校已确认签发”“录取结果有效”或“已完成入学”。

## 7. 阅读顺序与字段提取

解析器不信任 OCR 返回的 `OcrSpanV1` 数组顺序。
`span_geometry_v1()` 先从每个非退化四点多边形计算归一化包围矩形；
`reconstruct_reading_order_v1()` 再按纵向中心、边界坐标和 `span_id` 稳定排序，把文字分组为 `VisualLineV1`，并在每行内从左到右组成 `TextRunV1`。
需要跨行识别时，`forward_run_paths_v1()` 只探索最多三行且数量有上限的几何相关路径，避免对整页文本进行无界组合。

模板匹配只为每一页构造一次 `ReadingOrderV1`。页面匹配成功后，
字段提取会复用同一个、仅在当前调用栈内存活的 reading 对象，
既避免第二次几何重建，也不会跨调用或跨采集缓存 OCR 数据。

随后，字段规则在有界纵向区域和局部锚点语法中运行：

1. `_name_candidates_v1()` 只读取 `同学` 前连续的汉字或间隔点，并要求该文本片段前后除允许的结构标点外没有其他内容。
2. `_province_candidates_v1()` 从 `经` 开始，在最多三条相关文本行内寻找完整的招生委员会和 `批准` 句式；省份必须精确命中封闭名称表。
3. `_college_candidates_v1()` 从 `你被录取到我校` 后开始，在第一个受支持的教学单位后缀处结束；同一行不足时，只允许使用一条几何相关的下一行 `TextRunV1` 补全。
4. `_major_candidates_v1()` 读取 `专业学习` 前的专业名称。
   当前行本身已经合法时不会再拼接上一行；只有当前片段不完整时，才考虑一条非教学单位、几何相关的上一行，从而避免把无关说明文字并入专业名称。

每个候选都保留参与取值的精确 `source_span_ids`，并尽可能通过 `source_polygon_for_spans_v1()` 生成来源矩形。
同一页出现多个合法候选时，`_decision_from_candidates_v1()` 不会按位置或分数挑选，而是返回 `AMBIGUOUS`。
跨页聚合采用同样的保守原则，因此结果不依赖输入顺序。

## 8. 权威、存储与清理

`PrivateAdmissionNoticeExtractionServiceV1` 的构造受到模块内令牌保护，只能通过 `_create_for_coordinator_v1()` 由 `CaptureCoordinatorV1` 创建。
协调器唯一的提取入口是 `_process_private_admission_notice_extraction_v1()`：它只接收不透明 OCR 收据、精确的 `RegisteredWorkV1` 父工作和当前 `CaptureEpochV1`，也只返回 `StoredAdmissionNoticeExtractionV1`，不会把字段明文带出私有边界。

安全与生命周期属性包括：

- `_register_extraction_child_v1()` 强制要求 `OCR_INFERENCE` 父工作，并只注册 `ADMISSION_NOTICE_EXTRACTION` 子工作；
- `_require_live_v1()` 在每个敏感边界验证采集状态、会话代次、`PrivateEvidenceAuthorityV1` 和 `WorkFenceV1`；
- 通过子级 `CAPTURE_EVIDENCE_READ` 与 `CAPTURE_EVIDENCE_AUXILIARY` 工作访问存储；
- `put_admission_notice_extraction_v1()` 使用既有的每采集 AES-256-GCM DEK，将 canonical JSON 存为加密 `AUXILIARY_CANONICAL_JSON` 记录；
- 提交前重新核对来源 OCR 记录、canonical 内容、摘要、`CaptureSetV1.profile_id` 和字段溯源关系；
- 在同一临界区内完成幂等复用或新记录插入；加密、容量检查或元数据提交失败时，恢复记录表、索引和容量计数；
- `AdmissionNoticeExtractionServiceErrorV1` 只携带稳定原因码，`AdmissionNoticeExtractionV1.__repr__()` 与 `StoredAdmissionNoticeExtractionV1.__repr__()` 均隐藏字段值和私有来源；
- `retire_capture_v1()` 取消指定采集的活跃提取工作，`close_admission_v1()` 关闭新请求并取消全部剩余工作；
- `EndCapture` 清理流程先销毁采集 DEK，再清除密文和索引；密钥销毁后无法再以密码学方式恢复提取记录。

服务会在 `finally` 中清理暂存的 Python 引用，但 Python 不保证分配器级别的明文覆写。
安全属性是有界私有访问和采集 DEK 销毁，不是“每一个临时字节都已被物理覆盖”的声明。

普通处理程序、插件、HTTP/WS 路由、Manager 和浏览器都没有读取接口。
协调器中的 `_read_private_admission_extraction_for_test_v1()` 仅供授权测试使用，不能成为生产集成入口。
日志和支持包必须排除 OCR 文本、字段值、`source_span_ids`、`source_polygon`、帧/结果/采集 ID、能力令牌，以及序列化的 `SanitizedAdmissionContextV1`。

## 9. 稳定的私有失败结果

以下是 `AdmissionNoticeExtractionFailureReasonV1` 的内部原因码，不是当前浏览器或 HTTP 协议直接返回的结果：

| Reason | 含义 |
|---|---|
| `EXTRACTION_INPUT_INVALID` | 收据、页面、schema 或溯源输入格式错误、重复、缺失，或者来源 OCR 记录不存在 |
| `EXTRACTION_TEMPLATE_NOT_MATCHED` | 模板匹配器返回 `NOT_MATCHED` |
| `EXTRACTION_TEMPLATE_INSUFFICIENT` | 模板匹配器返回 `INSUFFICIENT` |
| `EXTRACTION_RESULT_TOO_LARGE` | 有界的加密辅助存储容量无法接纳结果 |
| `EXTRACTION_AUTHORITY_INVALID` | `PrivateEvidenceAuthorityV1` 已失效，或协调器不再拥有该采集 |
| `EXTRACTION_STALE` | 采集状态、会话代次或工作准入已经变化，或者任一 `WorkFenceV1` 校验失败 |
| `EXTRACTION_INTERNAL_ERROR` | 完整性、不变量、私有 codec、加密或意外私有处理失败，服务按失败关闭处理 |

`PrivateEvidenceStoreV1` 报告完整性、不变量或记录类型错误时，`_map_store_error_v1()` 还会调用协调器提供的 `_fail_protocol_runtime_v1()`，使当前安全采集进入失败关闭状态。
异常文本只包含稳定原因码，不会携带 OCR 文本、字段值或来源坐标。

## 10. 当前集成边界与发布阻断项

`CaptureCoordinatorV1` 在创建时一定会构造 `PrivateEvidenceStoreV1` 和 `PrivateAdmissionNoticeExtractionServiceV1`；
具备安全释放授权时，还会构造 `AdmissionNoticeSafeReleaseServiceV1`。
OCR 的生命周期不同：`CaptureCoordinatorV1._ocr_service_v1` 初始值始终为 `None`。
`ChatEngine` 只负责验证并暂存 `OcrDeploymentConfigV1`，再把该配置交给会话所有者；暂存配置本身不会创建客户端，也不会安装 `PrivateOcrServiceV1`。

会话所有者专用的完整内部调用链如下：

1. 由 `ChatSession._bootstrap_certificate_ocr_v1()` 调用 `CaptureCoordinatorV1._bootstrap_private_ocr_runtime_v1()`；
   后者创建 UDS 客户端，并通过 `_install_private_ocr_service_v1()` 安装 `PrivateOcrServiceV1`；
2. 安装成功后，由 `ChatSession._process_certificate_ocr_frames_v1()` 调用 `_process_private_ocr_frames_v1()`，处理已加密保存的图像帧并取得 OCR 收据；
3. 由 `_process_private_admission_notice_extraction_v1()` 调用 `PrivateAdmissionNoticeExtractionServiceV1.extract_v1()`，完成模板判定和四字段提取；
4. 在存在安全释放服务时调用 `stage_extraction_v1()`，暂存该加密收据供 `EndCapture` 内部重新读取。

但是，生产 `seal_capture_protocol_v1()` 最终进入 `_execute_seal_attempt_v1()` 后不会调用上述函数。
它只检查 `_test_processor_v1`，注册 `CAPTURE_MOCK_PROCESSOR`，并启动 `_run_mock_processor_v1()`。
有效的 `OcrDeploymentConfigV1` 只能成为经过验证的待用配置；只有会话所有者实际调用 `_bootstrap_certificate_ocr_v1()` 且初始化成功后，协调器才会安装 OCR 服务。
当前 Seal 路径既不会调用该初始化函数，也不会连接到提取或安全释放。

生产发布因此必须分别通过两道门禁：

1. 在 `_execute_seal_attempt_v1()` 中实现并审查 `_process_private_ocr_frames_v1()` → `_process_private_admission_notice_extraction_v1()` → `AdmissionNoticeSafeReleaseServiceV1.stage_extraction_v1()` 的精确组合，同时保持父工作、取消、清理和失败语义；
2. 配置并验证真实隔离 CPU OCR 的锁文件、模型、推理身份、UDS 策略、性能/资源上限和验收证据。

不得通过新增公共提取端点、浏览器 OCR、明文文件/数据库存储、远程回退、绕过 `WorkFenceV1` 的直接调用，或伪造成功结果的处理器来填补缺口。

## 11. 维护规则

- 四字段边界必须保持精确：`name`、`source_province`、`college`、`major`。
- 可信学校必须由服务端持有，并与 OCR 输出分离。
- 保留字段级弃答；不得按页面顺序、`raw_engine_score`、模糊相似度或 LLM 在冲突中选择。
- 修改 `HbtcAdmissionNoticeTemplateMatcherV1`、字段候选函数或归一化函数时，必须升级 `AdmissionNoticeExtractionIdentityV1` 中对应的版本，并增加迁移/复用测试。
- 其他学校、模板或通用证书类型应作为新的版本化设计，不得成为 V1 中未经审查的运行时插件。
- 保留严格 schema、字节/计数上限、溯源验证、脱敏表示、仅加密持久化和密钥优先清理。
- 字段集合变化时，必须独立审查 `AdmissionNoticeSafeReleaseServiceV1` 和 `SanitizedAdmissionContextV1` 的字段白名单；
  提取器新增的字段不会自动获得进入 `PUBLIC_CHAT` 的权限。
- 始终区分模板兼容与真实性、签发方验证、录取状态和入学声明。

## 12. 专项验证

字段提取测试与固定模板匹配测试所在目录包含同名测试模块，因此必须按功能目录分别执行，不能合并为一次 pytest 收集。
命令中的 `milestone_6b` 和 `milestone_6c` 只是仓库保留的实际目录名，不表示本文的功能分层：

```bash
PYTHONPATH="$PWD:$PWD/src" .venv/bin/pytest -q tests/chat_engine/milestone_6b
PYTHONPATH="$PWD:$PWD/src" .venv/bin/pytest -q tests/chat_engine/milestone_6c
```

| 套件范围 | 主要证据 |
|---|---|
| 契约与解析规则 | [`test_contracts_and_extractor.py`](../../tests/chat_engine/milestone_6b/test_contracts_and_extractor.py) 覆盖严格 schema、四字段规则、规范序列化和脱敏表示 |
| 歧义与页面顺序不变性 | [`test_ambiguity_and_multiframe.py`](../../tests/chat_engine/milestone_6b/test_ambiguity_and_multiframe.py) 覆盖候选冲突、跨页聚合、重复内容和输入顺序变化 |
| 私有授权、加密存储、竞争与清理 | [`test_private_store_authority_lifecycle.py`](../../tests/chat_engine/milestone_6b/test_private_store_authority_lifecycle.py) 覆盖精确父工作、陈旧回调、幂等复用、容量与密钥销毁 |
| 注入与普通数据出口隔离 | [`test_injection_and_isolation.py`](../../tests/chat_engine/milestone_6b/test_injection_and_isolation.py) 覆盖提示注入文本、日志表示和非授权读取路径 |
| 固定模板兼容性与对抗性布局 | [`test_template_compatibility.py`](../../tests/chat_engine/milestone_6c/test_template_compatibility.py) 覆盖错误学校、拆分标题、页脚文本、锚点错序和布局干扰 |
| 模板判定与字段提取交互 | [`test_extraction_interaction.py`](../../tests/chat_engine/milestone_6c/test_extraction_interaction.py) 验证只从单页 `MATCHED` 页面取值，以及冲突页面优先拒绝 |
| 合成性能冒烟 | 两个功能测试目录中的 `test_performance_smoke.py` 验证有界合成输入下的执行预算 |

这些套件使用合成 `OcrPageResultV1` 和测试夹具，只能证明确定性规则、授权边界和存储行为满足当前单元/集成测试。
它们不会验证真实 Paddle/PP-OCRv6 模型、相机成像质量、真实文档总体、指定 CPU 类型，也不会证明生产 Seal 已经接通。

## 13. 相关文档

- [技术报告](technical-report.md)
- [部署指南](deployment-guide.md)
- [运维与验证](operations-validation.md)
- [Secure Certificate Capture V1 规范修订](../../docs/en/reference/secure-certificate-capture-v1.md#current-admission-notice-roadmap-amendment)
