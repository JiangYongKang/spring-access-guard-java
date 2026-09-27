# spring-access-guard-java

本地可运行的 Spring Boot 访问控制服务：内置内存存储维护账号、凭据与失败记录，
认证、授权与滥用防护在所有入口下给出一致且可解释的结论。

## 凭据模型

- 凭据传输形态为 `tokenId.signature`，`signature` 是对 `tokenId` 的 HMAC-SHA256（密钥见
  `access-guard.token-secret`）。服务端保存每张凭据的状态（所属账号、过期时刻、是否吊销）。
- 校验结论可区分（`TokenStatus`），不会统一报成“认证失败”：
  - `MALFORMED`：格式不合法（结构、分隔符错误）；
  - `TAMPERED`：签名不匹配或非本服务签发（被篡改/伪造）；
  - `EXPIRED`：签名有效但已过有效期（`ttl` 见 `access-guard.token-ttl-seconds`）；
  - `REVOKED`：签名有效但已被吊销（含被刷新轮换掉的旧凭据）；
  - `VALID`：通过。
- **刷新即轮换**：`POST /auth/refresh` 在同一临界区内先吊销旧凭据再登记新凭据，
  并发刷新同一凭据时至多产生一个有效后继，其余调用得到 `REVOKED`，不会出现状态错乱。
- `POST /auth/revoke` 吊销凭据，立即生效。

## 角色模型与授权语义

- 角色为 `USER` / `ADMIN`，`ADMIN` 覆盖 `USER`（`Role.covers`）。
- 凭据不固化角色：授权判定（`AuthorizationService`）先校验凭据，再读取账号存储中的
  **实时角色**。因此角色调整后立即生效，同一请求在同一时刻只会得到一个结论，
  调整后的结论对后续所有请求一致稳定。
- 判定结论可区分（`Decision`）：
  - `DENY_UNAUTHENTICATED`（HTTP 401）：未通过认证，响应中附带具体 `tokenStatus`；
  - `DENY_FORBIDDEN`（HTTP 403）：已认证但角色不足；
  - `ALLOW`（HTTP 200）。
- 预置演示账号：`alice/alice-pass`（USER）、`admin/admin-pass`（ADMIN+USER）。

## 失败统计与锁定语义

- `FailureTracker` 按 **(账号, 来源)** 维度统计失败（来源取 `X-Source` 头，缺省为远端地址）：
  - 连续失败达到 `access-guard.max-failures` 次即临时锁定
    `access-guard.lock-seconds` 秒；
  - 锁定期间即使凭据/口令正确也按锁定原因拒绝（HTTP 429，`DENY_LOCKED`）；
  - 锁定到期自动恢复并重新计数；登录成功清除该 (账号, 来源) 的计数；
  - 计数按 (账号, 来源) 隔离：异常来源不会拖垮同一账号的其他来源或其他账号；
  - 记录条数上限为 `access-guard.max-tracked-entries`，满员时优先清理已恢复的过期记录，
    再淘汰最久未更新的记录，内存不会无限增长；
  - 计数与锁定状态按条目串行化，高并发下不丢计数。

## HTTP 入口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth/login` | 口令登录签发凭据（受失败锁定保护） |
| POST | `/auth/refresh` | 刷新（轮换）凭据 |
| POST | `/auth/revoke` | 吊销凭据 |
| GET | `/api/user` | 需要 USER 角色 |
| GET | `/api/admin` | 需要 ADMIN 角色 |

## 本地验证

```bash
# 运行全部测试（含并发刷新、越权、锁定与到期恢复、过期与吊销场景，
# 单测日志会打印输入与判定依据）
mvn test

# 启动服务（默认随机端口，可用 --server.port=8080 指定）
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

# 手工验证示例
curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'
TOKEN=<上一步返回的 token>
curl -s localhost:8080/api/user  -H "Authorization: Bearer $TOKEN"   # 200 ALLOW
curl -s localhost:8080/api/admin -H "Authorization: Bearer $TOKEN"   # 403 DENY_FORBIDDEN
curl -s localhost:8080/api/user                                       # 401 DENY_UNAUTHENTICATED
curl -s -X POST localhost:8080/auth/revoke -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}"
curl -s localhost:8080/api/user -H "Authorization: Bearer $TOKEN"    # 401 + tokenStatus=REVOKED
```
