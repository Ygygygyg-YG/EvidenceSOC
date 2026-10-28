# Task13 显式模型身份阶段设计（已选择免费工程A）

用户通过问题call_0218007d72214882a172ba116d92222d/0实际选择“采用A：先完成新身份方案的免费工程（推荐）”。具体提案原字节SHA256为054c92603f8a0c15fea9ee8fdcbbf66c7b50bd0f9468369103f11083dece521f。真实决定单独保存在主工作区活动根development/model-identity-engineering-20261028/engineering-consent.json。该决定采用工程设计，不授权真实身份登记、停机迁移、模型调用或具体处置批准。

## 目标和授权边界

继续使用原campaign.sqlite及原有100元总额、15元累计开发、30元补充、6元补充开发、16元回归、6元F8和2元未知保留限额。旧global模型身份、halt、3350行前缀、epoch0/1/2、51条补充开发请求和全部实际结果不改写；旧流程保持停止。新代码只在D:/传智杯/.backups/task13-model-identity实现；旧3e58411工作树及原分析数据保持原样。

当前工程新增供应商请求0。测试仅用专属临时SQLite与mock transport；已授权免费本机验收只可提取本机服务连接，不提取模型密钥。准备的新候选没有真实登记或发送权限。保持原单一slot9来源、观察、封印、知识、提示词、三类模拟行动和合法null语义；不更改backend模型/节点/分析兼容规则来强制计划。

## 数据与权限

新增独立model_identities模块，控制侧显式追加模型身份manifest及其独立外部采用authority，绑定原预算身份/路径、已登记的精确source epoch/source/config、确切响应模型和非空fingerprint、前任模型记录、继承的全局身份/halt快照、两份旧停机证据摘要、显式身份用途范围。身份用途范围仅限制身份可用于哪些已独立授权的阶段，不提供这些阶段的出站或计划批准权限。未来176/F8仍须其原有独立确认。

manifest不包含其完整authority或后续确认单摘要，以避免自引用。外部authority包含最终manifest摘要、采用决定和具体确认单摘要，数据库追加链同时绑定两者。工程A决定的类型与真实采用authority严格不同，不能混用。

冻结依赖顺序为core/source receipt/source epoch → identity manifest → 具体确认单 → 外部采用authority → 最终host manifest。确认单不能直接或间接引用最终authority摘要；它只固定身份manifest并描述所需采用权限。只有后生成的host manifest固定authority摘要，从而避免确认单与authority的第二类摘要循环。

core_config可选model_identity描述符为{id,response_model,fingerprint}；保留original_observed_model_binding作为历史锚点。最终identity manifest摘要位于独立的可选model_identity_binding={model_epoch_id,model_identity_sha256}，随源epoch执行绑定/请求显式传入，不能放回被manifest绑定的core形成环。无该可选字段的旧序列化和哈希完全不变。source v1 manifest不增字段、不改历史。

## 账本与停机

BudgetAccount只增加事务内派发守卫扩展点，原总额/开发限额预留逻辑继续复用。SupplementBudgetAccount显式身份模式要求已存在的source与model登记；构造只读，每次预留事务检查二者为最新、身份hash/用途匹配、无新身份停机。结算仍接受已退役但原映射正确的请求，不能因退役或停机丢费用。请求到model记录的映射与原预留、source映射同一事务追加，禁止UPDATE/DELETE；物理稳定键保留旧形状，身份归属独立映射并进入审计，防止换身份绕过语义重放。

require_model_identity_in_transaction及其只读入口显式接收purpose；host、worker和账户传入实际用途，预留事务内重新检查。用途不由manifest自动选择或扩展。

新身份只允许在显式采用记录中限定地承接原observable model version changed停机；原config身份和halt不删除、不替换。余额/认证/403/超出费用上界/未知原因等全局停机不可承接。SQL持久事件捕获全局非身份停机，防止旧进程随后写身份停机掩盖前因；缺失或篡改所需schema/链时显式身份路径拒绝。

新身份响应缺少模型/指纹或发生漂移时，在结构解析之前保存持久model halt并提交，再抛错；原始响应、usage及费用仍保留并结算。旧账户继续原global行为并保持停机。新作用域摘要区分历史halt与effective_halted，不将旧global停止误报已清除。

## 宿主、worker和计时

新身份引用贯穿E registration/request/account/ledger、claim provenance、预GO、worker入场、独立raw HTTP身份核验和计时来源。守卫在传模型密钥/启动付费容器前只读核对已登记身份，并在预算预留事务内再次核对。request、runtime options和core描述符不一致时拒绝。

no_plan独立验证不能只相信ledger自报身份；显式路径检查raw响应、物理账本及采用记录一致后才验证null。理由仍可缺失，合法null停止依赖派发且无计时信用；规则回退不获得计划/null信用。计时provenance的固定字段集合条件加入同一身份引用，禁止跨身份拼接批准与六分支结果。176宿主和v3请求接通相同守卫，仅做免费工程，不运行176或F8。

## 验证与交付

先验证旧预算模型/source epoch相关101项基线；初次Windows权限失败及第二次测试URI解析错误保留，修正测试环境后native final基线通过。新行为逐项先失败后实现。覆盖：真实采用与工程决定区分、旧停机保留、401/402/403/费用停机不可绕过、身份缺失/漂移、费用结算、并发原限额、映射原子性、跨source/model重放、旧哈希兼容、host/worker拒绝串用、null/回退和计时来源。

完成聚焦和适当联合验证、独立审查后才冻结新提交、导出源码并准备具体新候选。原预算及旧工件前后只读核对，供应商调用0，实际身份登记0、真实批准0、完整计时0/3。新候选的实际发送确认是本阶段完成后的独立步骤。
