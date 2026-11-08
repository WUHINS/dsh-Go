# 网页登录主机（dsh-webui-oauth）验证记录

远程主机的第三种接入方式：主机运行 `dsh-webui-oauth` 0.8.3+，App 用 RFC 8628 设备码换设备令牌，再由插件在服务端换发核心 `dsh-auth-*` Cookie。传输就是普通 HTTPS，因此能力与本地 `dsh web` 一致，不经过中继的 allow-list。

## 实现范围

| 层 | 位置 |
|---|---|
| 设备流程 / URL 规则 / core-session | `packages/dsh_oauth/` |
| Bearer 支持（HTTP 与 WebSocket 升级） | `packages/dsh_client/lib/src/connection.dart`、`session_api.dart` |
| 主机配置、链接、状态机 | `app/lib/remote/oauth/` |
| 主机列表、秘密、激活主机 | `app/lib/state/hosts_state.dart`、`connection_state.dart`、`read_list_identity.dart`、`notify_state.dart` |
| 表单与列表 | `app/lib/ui/remote/oauth_host_form.dart`、`remote_screen.dart` |
| 文案 | `app/lib/l10n/parts/oauth_{zh,en}.arb` |

## 契约（对应插件 0.8.3）

- `POST /dsh-webui-oauth/device/authorize`：`client_id=dsh-app`、`client_name` 必填；返回 `device_code / user_code / verification_uri{,_complete} / expires_in / interval`。
- `POST /dsh-webui-oauth/device/token`：`grant_type=urn:ietf:params:oauth:grant-type:device_code`；`authorization_pending` / `slow_down` 继续轮询，`expired_token` / `access_denied` / `invalid_grant` 终止。
- `POST /dsh-webui-oauth/device/core-session`：仅设备 Bearer；返回 `cookie_name / cookie_value / authority`。launch token 不离开主机。
- 设备令牌只存 `sha256`；App 侧存 Keystore（`oauth.<id>.token`）。主机上可随时吊销。
- `http://` 只允许内网地址：10/8、172.16/12、192.168/16、127/8、169.254/16、100.64/10，以及 IPv6 `::1`、fc00::/7、fe80::/10（含 IPv4-mapped）；`localhost` 例外。其他一律 `https://`。

## 已执行

```bash
(cd packages/dsh_oauth && dart analyze && dart test)        # 17 passed
(cd packages/dsh_client && dart analyze lib)                # clean
(cd packages/dsh_client && dart test test/bearer_test.dart test/client_test.dart)  # 19 passed
(cd app && flutter analyze lib)                             # clean
(cd app && flutter test test/remote/oauth_link_test.dart test/remote/oauth_state_test.dart \
                       test/remote/oauth_form_test.dart test/remote/hosts_state_test.dart)  # 43 passed
python3 app/tool/l10n_merge.py --check                      # 56 parts / 5858 keys
python3 app/tool/guide_sync.py --check                      # 03-engine-hosts 无问题
dart format --output=none --set-exit-if-changed <changed>   # clean
```

覆盖点：URL 策略（含公网 http 拒绝、IPv4-mapped）、authorize 请求体、`authorization_pending`/`slow_down`、core-session 的 Bearer 与响应解析、吊销后的终止错误、404 旧插件的提示、缺失令牌时不发请求、配置与令牌的持久化/删除、HostRef 编解码、表单在未授权时禁用保存、公网 http 在发请求前就地报错、网页版解析到主机对外地址。

## 真实链路（2026-11-08，本机隔离实例）

`dsh 0.2.2-rc.1` + `dsh-webui-oauth 0.8.3`（`link:` 安装到临时 profile，独立 `DSH_HOME`，`127.0.0.1:18080`）：

| 步骤 | 结果 |
|---|---|
| 未登录 `GET /api/sessions/list` / `GET /` | 401 / 302 → 登录页 |
| setup token 建号（`e2e` / 强密码） | `{ok:true}` + `dsh_wua_session` |
| `device/authorize` → `device/approve` → `device/token` | 短代码批准，拿到 `device_id` 与 Bearer |
| `device/core-session` | `{ok:true, cookie_name:"dsh-auth-…", authority:"127.0.0.1:18080"}` |
| `dart run tool/e2e_probe.dart` | `health: ok`、`mux: connected`、`sessions: 0` |
| App `OauthHostLink` 实连（`test/remote/oauth_live_test.dart`） | 通过 |
| 主机吊销设备后用旧令牌 | `device-token-required`（HTTP 401） |
| 重新授权 | 新 `device_id`，探针再次通过 |

### 发现并修复的插件问题（0.8.3）

`installRouteGate` 的 `gateResource` 为 Fetch 风格路由重建请求时只带 `cookie`，丢掉了 `authorization`：

```js
const headers = { cookie }
if (!checkRequest({ method, url, headers })) return new Response('unauthorized', ...)
```

0.2.2-rc.1 的 `/` fallback 与 `/api` 都走 resource，因此设备 Bearer 在这些路由上被判未认证；`device/core-session` 内部 `GET /?token=` 得到 401，插件返回 `core-session-unavailable`。修复是把 `authorization`（以及需要时的 `host`）一并传入，改动三行。该修复只加在本地验证副本，App 侧不需要改动；发布版需要包含它。

## 未执行（证据边界）

- **没有真实反向代理 / TLS**：真实链路是回环 HTTP；Host 改写 + `hostHeader`、Caddy/nginx 的 WebSocket 与大 body 行为只做了单元级校验。
- **没有真机**：OIDC 设备码在浏览器/自定义标签页的往返、App 回前台后的轮询恢复未实测。
- **没有跑 golden**：本机缺少 Noto CJK 字体，golden 用替代字体无法作为证据；相关测试未纳入本轮。
- 200 MiB 附件、断网重连、跨网络切换未做端到端验证。

## 部署前提

1. 主机装 `dsh-webui-oauth` ≥ 0.8.3，`dsh web` 只监听回环，由反代终结 TLS。
2. `client-connection.trustedHosts` 必须包含对外 authority，否则 `/api/remote.mux` 升级会被核心 Host fence 拒绝。
3. 反代需支持 WebSocket、不缓冲、读超时 ≥ 10 分钟、body 上限 ≥ 300 MiB。
4. 设备令牌等同于该 dsh 的完整权限：只走 TLS，按需吊销，别把审批页裸露在公网。
