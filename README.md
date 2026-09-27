# spring-access-guard-java

一个**纯本地、零外部中间件**的 Spring Boot 访问控制服务：用内置存储维护账号、
凭据（访问令牌）和失败记录，让**认证、授权、滥用防护**在登录、刷新、受保护 API
等所有入口下得到一致且可解释的结论。

- Java 21 / Spring Boot 3.4 / Spring Web，仅内存存储，`mvn spring-boot:run` 即可运行。
- 每个失败原因都是独立的枚举值，HTTP 层映射为不同的状态码与 `reason` 字段，
  不会把“过期 / 被吊销 / 被篡改 / 格式错”混成一个认证失败。

---

## 1. 快速开始

```bash
mvn spring-boot:run
# 种子账号（启动时写入）
#   admin / admin123   角色: admin, user
#   user  / user123    角色: user
```

登录拿凭据：

```bash
curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"user123"}'
# -> { "token": "<base64url(payload)>.<base64url(hmac)>", "subject":"user", ... }
```

访问受保护操作：

```bash
TOKEN='<上一步的 token>'

curl -s localhost:8080/api/profile -H "Authorization: Bearer $TOKEN"      # 任意已认证用户
curl -i localhost:8080/api/admin/panel -H "Authorization: Bearer $TOKEN"  # 需要 admin -> 403 FORBIDDEN
```

刷新与吊销：

```bash
curl -i -X POST localhost:8080/auth/refresh -H "Authorization: Bearer $TOKEN"  # 轮换，旧凭据失效
curl -i -X POST localhost:8080/auth/logout  -H "Authorization: Bearer $TOKEN"  # 吊销 -> 204
```

运行测试（含并发刷新、越权、锁定到期、过期/吊销等场景，日志会打印输入与判定依据）：

```bash
mvn test
```

> 实际端口默认随机（`server.port=0`）。本地手动验证可在命令行加
> `--server.port=8080`，或改 `src/main/resources/application.properties`。

---

## 2. 凭据模型（签发 / 校验 / 刷新 / 吊销）

### 2.1 令牌结构与服务端状态

令牌是紧凑的签名串：

```
base64url(payloadJson) . base64url(HMAC_SHA256(payload, secret))
```

payload 声明：`jti`（唯一 id）、`fam`（轮换族 id）、`sub`（账号）、
`iat`（签发毫秒）、`exp`（过期毫秒）。HMAC 比对使用恒定时间比较。

令牌只证明“身份”，**不含角色**。服务端 `LocalTokenStore` 为每个 `jti` 保存状态：

```
LIVE ──刷新轮换──▶ ROTATED ──(过了重用宽限期再次出现)──▶ REVOKED（整族）
  └──────────────吊销──────────────▶ REVOKED
```

### 2.2 校验时的判定顺序（原因严格可区分）

`TokenService.verify` 自上而下，第一层失败即返回对应原因，因此永远能拿到最具体、
最稳定的结论：

| 顺序 | 检查 | 原因 `RejectionReason` | HTTP |
| --- | --- | --- | --- |
| 1 | 没有/空白凭据 | `MISSING_TOKEN` | 401 |
| 1 | 不是 `a.b` 形态、base64/JSON/声明非法 | `MALFORMED_TOKEN` | 401 |
| 1 | 形态合法但签名不匹配（篡改） | `BAD_SIGNATURE` | 401 |
| 2 | 签名对，但 `jti` 不在服务端存储 | `UNKNOWN_TOKEN` | 401 |
| 2 | 已显式吊销 | `REVOKED` | 401 |
| 2 | 已被轮换走（保护入口上使用旧凭据） | `REUSE_DETECTED` | 401 |
| 3 | 已过 `exp` | `EXPIRED` | 401 |

**吊销优先于过期**：一个被吊销的令牌即使后来也过期了，仍然报 `REVOKED`，
审计结论不会随时间漂移。`MALFORMED_TOKEN` 与 `BAD_SIGNATURE` 的分界是：结构/编码/
声明层面的问题算 malformed；结构完全合法、仅 MAC 对不上才算被篡改。

### 2.3 刷新：并发安全 + 重用检测

`POST /auth/refresh` 用服务端的**原子 compare-and-rotate**（`LocalTokenStore`
单一过渡锁）把旧令牌标为 `ROTATED` 并写入后继：

- **同一凭据被并发刷新**：所有调用在锁上串行化，只有第一个把状态从 `LIVE`
  改成 `ROTATED` 并拿到后继；其余调用观察到非 LIVE，返回
  `REFRESH_REJECTED`，**不产生第二个有效后继，也不改乱状态**。
- **轮换宽限期**（默认 30s，`access-guard.refresh-reuse-grace`）：轮换后短时间内
  再次提交旧凭据，判定为“并发竞态中迟到的请求”，返回 `REFRESH_REJECTED`，
  新凭据保持有效。
- **宽限期之后再次提交旧凭据**：这是令牌被盗后重用的强信号，返回
  `REUSE_DETECTED` 并**吊销整族**（包括当前有效的后继）。

### 2.4 吊销

`POST /auth/logout` 吊销单个 `jti`。家族级吊销发生在检测到重用时。
吊销是幂等的，对无法解析的令牌执行吊销是空操作。

---

## 3. 角色与授权模型

- 角色保存在账号存储里，令牌只携带身份；每次请求都从 `AccountStore`
  **实时读取角色**（live roles）。
- 因此**调整角色对已签发凭据立即生效**，不需要重新登录或等待令牌过期；
  管理员接口 `POST /api/admin/roles` 可原子替换某账号的角色集合。
- 单次请求内，账号记录与其角色集合是**不可变快照**（Java `record` + `Set.copyOf`），
  在判定开始时一次性读取，因此同一请求前后结论绝不会不一致。
- **未认证与已认证越权严格区分**：
  - 凭据层任何问题 → 401 系列（`MISSING_TOKEN/MALFORMED_TOKEN/BAD_SIGNATURE/...`）；
  - 凭据有效但缺少所需角色 → `403 FORBIDDEN`。
- 方法上用 `@RequireRole("admin")` 声明要求；`@RequireRole("")` 表示
  “任意已认证身份”；没有注解的方法是公开端点。统一由 `GuardInterceptor` 执行，
  与登录/刷新走同一个 `AccessGuard` 门面。

---

## 4. 失败统计、限流与临时锁定

所有入口（登录、刷新、受保护 API）都经过 `AccessGuard`，检查顺序完全一致：

```
来源限流  →  (账号, 来源) 锁定  →  凭据校验  →  角色授权
RATE_LIMITED   ACCOUNT_LOCKED      令牌/密码原因    FORBIDDEN
```

### 4.1 按 (账号 × 来源) 的失败与锁定

- 失败键是复合键 `(username, source)`，`source` 取 `X-Forwarded-For` 首跳或
  对端 IP。**因此异常来源无法把正常用户在其他来源一起锁掉，一个账号的失败也
  不会牵连另一个账号。**
- 滑动窗口内连续失败达到阈值（默认 5，`access-guard.lock-threshold`）即锁定到
  `now + lock-duration`（默认 5 分钟）。
- **锁定期间即使凭据正确也拒绝**，原因是 `ACCOUNT_LOCKED`（HTTP 423），
  与密码错误 `BAD_CREDENTIALS`（401）明确区分。
- **到期自动恢复**：锁定是基于时钟的判定，时间一过，下一次请求即恢复，
  旧失败计数清零，无需后台任务或人工解锁。
- 成功认证会清空该键的失败记录；超出失败窗口（默认 15 分钟）的旧失败自动滑出。

### 4.2 按来源限流

`SourceRateLimiter` 对每个来源维护滑动窗口时间戳（默认 60 次/分钟，
`access-guard.source-rate-limit` / `rate-window`），超限返回
`RATE_LIMITED`（HTTP 429）。它与账号锁**相互独立**：吵杂来源只会被限流，
不会因此锁账号；某账号被锁也不会连累同来源的其他用户。

### 4.3 高并发正确性与容量上限

- 每个键的计数变更在该键自己的监视器内完成，使用并发集合，
  **并发失败计数不会丢失**（测试以 16 线程并发 200 次失败断言计数精确等于 200）。
- 内部记录有硬性上限：`access-guard.max-tracked-accounts`（默认 10000）与
  `max-tracked-sources`（默认 10000）。达到上限时先清理过期/空闲项，
  仍不足则淘汰最久未使用且未锁定的项；**正在生效的锁定键不会被淘汰**。

---

## 5. 拒绝原因速查

| 原因 | 含义 | HTTP |
| --- | --- | --- |
| `MISSING_TOKEN` | 未携带凭据 | 401 |
| `MALFORMED_TOKEN` | 形态/编码/声明不合法 | 401 |
| `BAD_SIGNATURE` | 被篡改（MAC 不匹配） | 401 |
| `EXPIRED` | 已过期 | 401 |
| `REVOKED` | 已吊销（优先于过期） | 401 |
| `UNKNOWN_TOKEN` | 签名合法但服务端无此凭据 | 401 |
| `REUSE_DETECTED` | 宽限期后重用已轮换凭据，整族吊销 | 401 |
| `REFRESH_REJECTED` | 刷新竞态落败/凭据不可刷新 | 401 |
| `BAD_CREDENTIALS` | 账号不存在/被禁用/密码错误 | 401 |
| `ACCOUNT_LOCKED` | (账号, 来源) 被临时锁定，凭据对也拒绝 | 423 |
| `RATE_LIMITED` | 来源超出请求速率 | 429 |
| `FORBIDDEN` | 已认证但缺少角色（区别于 401） | 403 |

错误响应体形如：

```json
{ "timestamp":"...", "status":403, "error":"Forbidden",
  "reason":"FORBIDDEN", "message":"identity 'user' with roles [user] lacks required role 'admin'",
  "path":"/api/admin/panel" }
```

---

## 6. 配置项

见 `src/main/resources/application.properties`，前缀 `access-guard.*`：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `token-secret` | 开发占位密钥 | HMAC 密钥，生产必须更换 |
| `token-ttl` | 30m | 凭据有效期 |
| `refresh-reuse-grace` | 30s | 轮换后区分并发竞态与重用的窗口 |
| `lock-threshold` | 5 | 触发锁定的连续失败数 |
| `lock-duration` | 5m | 锁定时长 |
| `failure-window` | 15m | 失败计数滑动窗口 |
| `max-tracked-accounts` | 10000 | 失败/锁定记录上限 |
| `source-rate-limit` | 60 | 每来源窗口内最大请求数 |
| `rate-window` | 1m | 限流窗口 |
| `max-tracked-sources` | 10000 | 来源记录上限 |

---

## 7. 主要代码结构

```
security/
  AccessGuard.java                 统一门面（所有入口同一判定顺序）
  decision/                        RejectionReason 与 sealed 判定结果
  model/                           Account / StoredToken / AccountSource
  crypto/PasswordHasher.java       PBKDF2-HMAC-SHA256 加盐口令哈希
  token/
    TokenSigner / HmacTokenSigner  签发/解析，区分 malformed 与 bad signature
    LocalTokenStore                原子轮换/吊销 + 族索引
    TokenService                   校验、刷新、重用检测、过期/吊销优先级
  store/AccountStore.java          账号目录，原子角色替换
  auth/
    FailureTracker.java            按 (账号,来源) 失败计数 + 临时锁定 + 有界
    SourceRateLimiter.java         按来源滑动窗口限流 + 有界
  authorization/Authorizer.java    实时角色快照授权
web/
  GuardInterceptor.java            Bearer 提取 + 统一拦截
  ApiExceptionHandler.java         原因 -> HTTP 状态码/响应体
  AuthController.java              /auth/login|refresh|logout
  ProtectedController.java         /api/profile、/api/admin/panel、角色管理
config/                            Bean 装配、配置属性、种子账号
```

## 8. 测试覆盖

| 测试类 | 覆盖点 |
| --- | --- |
| `TokenVerificationTest` | 缺失/格式错/篡改/过期/吊销/未知六类原因可区分，吊销优先于过期 |
| `ConcurrentRefreshTest` | 16 线程并发刷新仅一个后继；竞态落败可解释；宽限期后重用整族吊销 |
| `AuthorizationTest` | 未认证 vs 越权可区分；角色调整对已发凭据即时生效；请求内结论稳定 |
| `LockoutTest` | 阈值锁定、正确凭据也拒、到期自动恢复、来源隔离、200 次并发计数无丢失 |
| `RateLimitAndBoundTest` | 来源限流与窗口恢复；失败表/来源表容量有上限 |
| `HttpEndpointsIntegrationTest` | 全栈 401/403/423/429 与 `reason` 字段、角色提升端到端 |

单测使用可拨时间的 `MutableClock` 确定性地验证过期与锁定恢复；
各用例通过 SLF4J 打印**输入**（账号/来源/要求角色/令牌前缀）与**判定依据**
（命中的原因与明细）。
