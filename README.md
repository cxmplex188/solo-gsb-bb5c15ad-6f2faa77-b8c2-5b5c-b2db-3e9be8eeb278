# Capability Token API

基于 **Python / FastAPI / SQLite** 的能力令牌（Capability Token）服务，为文件下载等
HTTP 操作签发**短期 HMAC 签名令牌**，并在使用时进行严格验证。无需任何第三方账号或外部
依赖（不需要 Redis、JWT 服务、对象存储账号等），单个 SQLite 文件即完整运行。

- 🔐 **HMAC-SHA256 签名**，令牌自包含、可离线验证（多用途令牌无状态）
- 🔗 **绑定 HTTP 方法与规范化路径**：令牌不能被挪用到其它动词或路径
- ⏱️ **短期有效**：签发时指定 TTL，服务端强制上限，过期即失效
- 🔁 **可选一次性 nonce**：成功使用后原子写入 SQLite，重放请求被拒绝
  （`BEGIN IMMEDIATE` + 主键唯一约束，并发请求只有一个能成功）
- 🚫 **主体级撤销**：管理员可按 `subject` 设置撤销截止时间，`iat ≤ 截止时间` 的令牌
  一律返回 `401 subject_revoked`；撤销判断与 nonce 消费在**同一 SQLite 事务**中完成，
  被撤销的令牌不会消耗 nonce，支持随时恢复
- 🚀 启动时自动初始化数据库，监听 **8000** 端口
- 🐳 提供 `Dockerfile` 与 `docker-compose.yml`，开箱即用

---

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── config.py        # 环境变量配置
│   ├── db.py            # SQLite：nonce 原子消费、主体撤销记录与过期清理
│   ├── tokens.py        # 令牌签发 / 解析 / 验证（HMAC 核心）
│   ├── schemas.py       # Pydantic 请求/响应模型
│   └── main.py          # FastAPI 路由与启动生命周期
├── files/               # 受保护的示例下载目录（compose 只读挂载）
│   └── hello.txt
├── tests/
│   └── test_api.py      # 32 个端到端测试（无需网络/容器）
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env          # 按需修改 CAPABILITY_SECRET
docker compose up --build
```

服务在 `http://localhost:8000` 启动，交互式文档位于
`http://localhost:8000/docs`。

### 方式二：本地运行

```bash
pip install -r requirements.txt
export CAPABILITY_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# 或：python -m app.main
```

> 未设置 `CAPABILITY_SECRET` 时，服务会在启动时生成**进程内随机密钥**，重启后所有旧令牌
> 失效（日志会有 WARNING）。开发可用，生产请务必固定密钥。

### 健康检查

```bash
curl http://localhost:8000/health
# {"status":"ok","time":1727000000}
```

## 使用流程

### 1. 签发令牌

```bash
curl -X POST http://localhost:8000/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "path": "/files/hello.txt",
    "ttl_seconds": 120,
    "one_time": true,
    "subject": "alice"
  }'
```

响应：

```json
{
  "token": "eyJleHAi...LjU...（base64url(payload).base64url(hmac)）",
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "method": "GET",
  "path": "/files/hello.txt",
  "issued_at": 1727000000,
  "expires_at": 1727000120,
  "expires_in": 120,
  "one_time": true,
  "subject": "alice"
}
```

请求字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `method` | 是 | 令牌绑定的 HTTP 方法（规范为大写），如 `GET`、`POST`、`DELETE` |
| `path` | 是 | 令牌绑定的路径，必须以 `/` 开头，如 `/files/hello.txt` |
| `ttl_seconds` | 否 | 有效期秒数；缺省用 `CAPABILITY_DEFAULT_TTL`，并被 `CAPABILITY_MAX_TTL` 截断 |
| `one_time` | 否 | `true` 表示一次性令牌，首次成功使用即失效 |
| `subject` | 否 | 令牌归属主体（如用户 ID），会写入签名负载 |
| `extra` | 否 | 任意额外 JSON 声明（同样受签名保护，篡改即签名失败） |

### 2. 使用令牌访问受保护资源（文件下载）

支持三种携带方式（任选其一）：

```bash
# 查询参数
curl -i "http://localhost:8000/files/hello.txt?token=<TOKEN>"

# Authorization 头（Bearer 或 Capability 方案均可）
curl -i -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/files/hello.txt

# 自定义头
curl -i -H "X-Capability-Token: <TOKEN>" \
  http://localhost:8000/files/hello.txt
```

一次性令牌**第一次成功下载返回 200**，再次使用返回：

```json
HTTP/1.1 401 Unauthorized
{"error":"nonce_replayed","detail":"one-time token has already been used"}
```

### 3. 独立验证令牌（不访问资源）

适合网关 / 其它服务在转发前做校验：

```bash
curl -X POST http://localhost:8000/tokens/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "<TOKEN>",
    "method": "GET",
    "path": "/files/hello.txt",
    "consume": true
  }'
```

- `consume: true`（默认）：若为一次性令牌且验证通过，会**真正消费 nonce**。
- `consume: false`：只做"演练"（dry run），不消费一次性令牌，可用于预检。

成功响应：

```json
{
  "valid": true,
  "method": "GET",
  "path": "/files/hello.txt",
  "expires_at": 1727000120,
  "expires_in": 97,
  "one_time": true,
  "consumed": true,
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "subject": "alice",
  "extra": {}
}
```

### 4. 主体撤销与恢复（管理员接口）

当某个主体（用户 / 客户端）的令牌泄露或需要整体下线时，可按 `subject` 撤销。
两个接口均受管理员密钥保护：设置 `CAPABILITY_ADMIN_KEY` 后须携带
`X-Admin-Key` 头；未设置时回退到 `CAPABILITY_ISSUER_KEY`。

```bash
# 撤销：alice 在「当前时间」及之前签发的所有令牌立即失效
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice"}'
# {"subject":"alice","revoked":true,"restored":false,"cutoff":1727000100,"purge_after":1727003700}

# 也可以显式指定撤销截止时间：iat <= cutoff 的令牌被拒绝，之后的照常可用
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "cutoff": 1727000000}'

# 查看当前生效的撤销记录
curl -H "X-Admin-Key: $ADMIN_KEY" http://localhost:8000/tokens/revocations
# {"revocations":[{"subject":"alice","cutoff":1727000100,"created_at":1727000100,"purge_after":1727003700}],"count":1}

# 恢复：删除撤销记录，未过期且 nonce 未被消耗的令牌重新可用
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "restore": true}'
# {"subject":"alice","revoked":false,"restored":true,"cutoff":null,"purge_after":null}
```

以上 curl 示例同样适用于 `docker compose up` 启动的部署（compose 把容器
8000 端口映射到宿主机）；只需在 `.env` 中配置密钥：

```bash
# .env
CAPABILITY_SECRET=<强随机密钥>
CAPABILITY_ADMIN_KEY=<管理员密钥>     # 也可只设 CAPABILITY_ISSUER_KEY，管理接口会回退使用它

docker compose up -d --build
docker compose logs -f capability-api
```

行为要点：

- 撤销记录**持久化**在 SQLite `subject_revocations` 表，服务重启后仍然生效；
- 撤销判断与一次性 nonce 消费在**同一个 `BEGIN IMMEDIATE` 事务**中完成：被撤销的
  令牌返回 `401 subject_revoked` 且 **nonce 不会被消耗**，恢复后令牌仍可正常使用；
- 重复撤销同一 `subject` 会**覆盖**旧的截止时间（可用于扩大或缩小撤销范围）；
- 每条记录带 `purge_after = cutoff + CAPABILITY_MAX_TTL`：超过该时刻后所有可能被
  撤销命中的令牌必然已过期，后台清理任务（每 10 分钟，启动时也会执行一次）会删除
  该记录，表不会无限增长；
- 不带 `sub` 的令牌不参与撤销，验证仍然完全无状态。

## 验证规则（核心）

`verify_token` 按以下顺序检查，任何一步失败立即返回稳定错误码：

1. **结构**：令牌必须为 `<base64url(payload)>.<base64url(signature)>`，payload 是 JSON 对象；
2. **签名**：`HMAC-SHA256(secret, payload)` 与令牌附带签名用
   `hmac.compare_digest` 常量时间比较，防止时序攻击；
3. **负载声明**：版本号 `v=1`，`m`/`p`/`jti` 为非空字符串，`iat`/`exp` 为整数且 `iat <= exp`，`one` 为布尔；
4. **过期时间**：当前时间 `>= exp` 即拒绝（`expired`）；
5. **方法绑定**：令牌方法 ≠ 请求方法返回 `403 method_mismatch`；
6. **路径绑定**：令牌路径 ≠ 规范化后的请求路径返回 `403 path_mismatch`；
7. **主体撤销 + 一次性 nonce（同一事务）**：若令牌带 `sub` 且该主体存在撤销记录，
   `iat <= cutoff` 返回 `401 subject_revoked`，**nonce 不被消耗**；否则当
   `one_time=true` 且 `consume=true` 时原子写入 `consumed_nonces`，已存在则返回
   `nonce_replayed`。两步在同一个 `BEGIN IMMEDIATE` 事务中完成，撤销与消费互不竞争。

### 路径规范化

签发与验证使用同一套规则（`app/tokens.py::canonical_path`），保证双方对路径的理解一致：

- 折叠重复斜杠（包括前导 `//`）；
- 解析 `.` / `..` 段；
- 去掉根路径以外的结尾 `/`。

因此 `/files/hello.txt` 与 `//files/./hello.txt/` 视为同一绑定。受保护下载端点还会在
文件系统层做 `Path.resolve()` 边界检查，杜绝目录穿越。

### 错误码

| `error` | HTTP 状态码 | 含义 |
| --- | --- | --- |
| `malformed` | 401 | 令牌格式/base64/JSON 错误 |
| `bad_signature` | 401 | HMAC 签名不匹配（令牌被篡改或密钥不同） |
| `bad_payload` | 401 | 负载声明类型/版本非法 |
| `expired` | 401 | 令牌已过期 |
| `subject_revoked` | 401 | 主体已被撤销（`iat` 不晚于撤销截止时间） |
| `nonce_replayed` | 401 | 一次性令牌被重复使用 |
| `method_mismatch` | 403 | HTTP 方法与绑定不一致 |
| `path_mismatch` | 403 | 路径与绑定不一致 |
| `validation_error` | 422 | 请求体未通过 Pydantic 校验 |

## 令牌格式

```
<base64url(payload_json)>.<base64url(hmac_sha256(secret, payload_json))>
```

负载（键按字典序排序的紧凑 JSON，全部纳入签名）：

```json
{
  "v": 1,
  "m": "GET",
  "p": "/files/hello.txt",
  "iat": 1727000000,
  "exp": 1727000120,
  "jti": "z1w6w4XPKcDQ2mkotgWgng",
  "one": true,
  "sub": "alice",
  "ext": {}
}
```

- 多用途令牌（`one=false`）且不带 `sub` 时**完全无状态**：只靠签名和过期即可验证，
  数据库不记录任何东西；带 `sub` 的令牌验证时需查询撤销表；
- 一次性令牌只在服务端记住一个不透明 nonce（`jti`），不存储令牌或负载内容。

## 一次性 nonce 的原子性（防重放）

`app/db.py` 使用 SQLite：

```sql
CREATE TABLE consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;
```

消费逻辑在一个 `BEGIN IMMEDIATE` 事务中执行
`INSERT OR IGNORE`，以 `rowcount == 1` 判定是否为首次使用。数据库级主键唯一约束会把
并发竞争串行化：**N 个并发重放恰好 1 个成功，其余全部拿到 `nonce_replayed`**
（测试 `test_15_concurrent_replays_only_one_wins` 及真实 HTTP 8 并发冒烟均验证过）。

`expires_at` 冗余入库，后台每 10 分钟（启动时也会执行一次）清除已过期行，保证表不无限增长。

## 主体撤销的持久化与清理

撤销记录与 nonce 存放在同一个 SQLite 数据库：

```sql
CREATE TABLE subject_revocations (
    subject     TEXT PRIMARY KEY,
    cutoff      INTEGER NOT NULL,   -- iat <= cutoff 的令牌被拒绝
    created_at  INTEGER NOT NULL,
    purge_after INTEGER NOT NULL    -- cutoff + CAPABILITY_MAX_TTL
) WITHOUT ROWID;
```

验证时，撤销检查（`SELECT`）与 nonce 消费（`INSERT OR IGNORE`）在**同一个
`BEGIN IMMEDIATE` 事务**中执行：要么发现撤销记录并整体回滚（nonce 原样保留），
要么成功消费 nonce 并提交。因此"撤销"与"用掉一次性令牌"这两个并发事件绝不会
互相穿插——被撤销主体的令牌不可能趁机烧掉 nonce，恢复后依然可用
（测试 `test_28_concurrent_verify_of_revoked_token_consumes_nothing` 用 12 线程验证）。

`purge_after = cutoff + CAPABILITY_MAX_TTL`：凡是 `iat <= cutoff` 的令牌，其
`exp <= cutoff + max_ttl`，超过该时刻后撤销记录不可能再命中任何未过期令牌，
后台清理任务会将其删除。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CAPABILITY_SECRET` | （启动时随机生成） | HMAC 签名密钥；生产必须固定并保密 |
| `CAPABILITY_ISSUER_KEY` | 空（签发不鉴权） | 设置后，调用 `/tokens/issue` 须带匹配的 `X-Issuer-Key` 头 |
| `CAPABILITY_ADMIN_KEY` | 空（回退到 `CAPABILITY_ISSUER_KEY`） | 设置后，调用 `/tokens/revoke-subject` 与 `/tokens/revocations` 须带匹配的 `X-Admin-Key` 头 |
| `CAPABILITY_DB_PATH` | `./data/capabilities.db` | SQLite 文件路径，启动自动建库建表 |
| `CAPABILITY_FILES_DIR` | `./files` | 受保护下载目录 |
| `CAPABILITY_DEFAULT_TTL` | `300` | 默认有效期（秒） |
| `CAPABILITY_MAX_TTL` | `3600` | 有效期硬上限（秒） |

> 签发鉴权是可选项：能力令牌通常由内部可信服务签发，因此用环境变量配置一个共享密钥
> 即可，无需用户体系或第三方账号。管理接口（撤销/恢复/列表）同理：未设置
> `CAPABILITY_ADMIN_KEY` 时回退使用 `CAPABILITY_ISSUER_KEY`；两者都未设置时管理接口
> 不鉴权（仅限本地实验，启动日志会给出 WARNING）。

## 运行测试

测试通过 FastAPI `TestClient` 在进程内运行，自动使用临时目录，不影响任何真实数据：

```bash
# 若环境里没有 pytest，直接用 unittest 运行也可以：
python tests/test_api.py
```

覆盖：签发与 TTL 截断、路径规范化、签发密钥门禁、签名篡改、负载篡改、方法/路径绑定、
过期、畸形令牌、一次性消费、dry-run、**12 线程并发重放只有 1 个成功**、无令牌下载、
三种携带方式、HEAD/GET 绑定、缺失文件、目录穿越、健康检查，以及主体撤销：撤销后
`subject_revoked` 且 nonce 不消耗、恢复后可用、截止时间边界、撤销列表、管理员密钥
门禁、**12 线程并发验证被撤销令牌无一消耗 nonce**、撤销记录过期清理等 32 个用例。

## 部署说明

- Compose 将 SQLite 放在命名卷 `capability-data`（`/data`），把宿主机 `./files`
  只读挂载到 `/app/files`；
- 容器以非 root 用户（uid 10001）运行，并内置 `/health` 健康检查；
- 多副本部署时 SQLite 文件需放在共享块存储上，或将本服务作为单实例网关运行；
  也可自行把 `Database` 替换为其它支持唯一约束的存储而不改动令牌核心逻辑。

## 安全建议

1. 生产环境始终设置强随机 `CAPABILITY_SECRET`，并通过密钥管理机制注入，不要提交到仓库；
2. TTL 尽量短（分钟级），需要防重放的场景使用 `one_time=true`；
3. 签发时带上 `subject` 并配置 `CAPABILITY_ADMIN_KEY`：令牌泄露时可立即按主体撤销，
   事后也可用 `restore` 恢复误伤；
4. 令牌应通过 HTTPS（TLS）传输，查询参数形式可能出现在访问日志中，敏感场景优先用请求头；
5. 轮换密钥时可在负载中引入 `kid` 并支持多密钥验签（当前版本固定单密钥）。
