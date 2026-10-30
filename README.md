# HTTP Digest Authentication · Part 1

**简体中文** | [English](README.en.md)

DI31002 信息安全课程第一部分项目：在现有 Python HTTP 服务器上实现摘要认证，并对比正常认证与有意植入的认证后门。本项目用于课程实验和本机演示。

## 项目作用

- **安全版服务器**：正确凭据可以读取受保护资源，缺失或错误凭据返回 `401 Unauthorized`。
- **后门版服务器**：正常认证仍然有效；指定的兼容分支允许以已注册用户身份免密访问，用于演示认证逻辑缺陷。
- **两个命令行客户端**：交互输入用户名、密码，获取认证挑战，显示最终 HTTP 状态码和正文。
- **自动验证**：覆盖 UTF-8 账户、参数解析、URI 绑定、nonce 过期、重放、并发、缓存容量和真实 HTTP 交互。

正常认证使用 SHA-256、`realm="DI31002"` 和 `qop=auth`。nonce 有效期为 300 秒，成功认证后立即失效，缓存最多保存 4096 条。

## 环境要求

- Python **3.10+**。
- Git，以及访问本仓库的权限；下面的克隆命令使用 GitHub SSH。
- 原服务器依赖 `urllib3>=2.3.0`；新增认证代码和客户端使用 Python 标准库。

以下命令适用于 Ubuntu、Linux 和 macOS 的 Bash 类终端。使用 Windows 时，可在 WSL 中按相同步骤运行。

## 1. 获取项目并安装依赖

```bash
git clone git@github.com:ganleming0-star/Information_sercurity_project_part1.git
cd Information_sercurity_project_part1/py-http-server-main

python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'urllib3>=2.3.0'
```

已经下载项目时，直接进入其中的 `py-http-server-main` 目录。后续服务器、客户端和测试命令均在该目录执行。

## 2. 配置本地账户

`passwords.txt` 是本地文件，已被 Git 忽略，因此新克隆的仓库需要先创建它。下面的命令仅在文件不存在时生成样例账户，已有文件会保留：

```bash
python - <<'PY'
from hashlib import sha256
from pathlib import Path

path = Path("passwords.txt")
if not path.exists():
    accounts = {"root": "password", "alice": "mushroom"}
    path.write_text(
        "".join(
            f"{username}:{sha256(password.encode('utf-8')).hexdigest()}\n"
            for username, password in accounts.items()
        ),
        encoding="utf-8",
    )
PY
```

新生成文件中的账户为：

| 用户名 | 原始密码 |
| --- | --- |
| `root` | `password` |
| `alice` | `mushroom` |

文件每行格式为 `username:SHA256(password)`，保存的是密码的 UTF-8 SHA-256 十六进制摘要。可以配置其他账户；服务器启动时读取文件，修改后需重启。空文件表示没有可登录账户。

## 3. 运行安全版

在第一个终端启动服务器：

```bash
python start_server_digest.py
```

在第二个终端进入同一服务器项目目录，激活环境并运行客户端：

```bash
cd Information_sercurity_project_part1/py-http-server-main
source .venv/bin/activate
python client.py http://127.0.0.1:8080/README.md
```

第二个终端的 `cd` 路径以你的实际克隆位置为准。按提示输入 `root` / `password` 或 `alice` / `mushroom`，将看到 `HTTP 200 OK` 和请求文件的内容。密码输入时不显示字符；错误密码返回 `HTTP 401 Unauthorized`。

URL 参数可省略，默认访问 `http://127.0.0.1:8080/`，也可以请求服务器目录中的其他文件。IPv6 示例：

```bash
python client.py 'http://[::1]:8080/README.md'
```

## 4. 演示后门版

两个启动脚本使用相同的 8080 端口，每次只运行一个。先在第一个终端按 `Ctrl+C` 关闭安全版，再启动后门版：

```bash
python start_server_subverted.py
```

在第二个终端先验证正常认证：

```bash
python client_subverted.py http://127.0.0.1:8080/README.md
```

这里仍然需要正确密码。随后显式启用后门演示：

```bash
python client_subverted.py --backdoor http://127.0.0.1:8080/README.md
```

输入已注册用户名，例如 `alice`，密码任意填写。客户端仍会询问密码，但后门模式的摘要计算不使用它。

| 请求方式 | 安全版 | 后门版 |
| --- | --- | --- |
| 正确账户及密码 | `200` | `200` |
| 正常认证、错误密码 | `401` | `401` |
| 已注册用户、`--backdoor` | `401` | `200` |
| 不存在的用户名 | `401` | `401` |

表中的 `200` 以请求文件存在为前提；通过认证后，文件不存在仍返回 `404`。后门仅在认证头同时省略 `qop`、`nc`、`cnonce` 时触发，该分支有意遗漏密码绑定。

## 5. 测试与字符统计

先按 `Ctrl+C` 关闭演示服务器，再执行：

```bash
python -W error -m unittest discover -s tests -v
python tools/count_digest_chars.py
```

完整测试包含真实回环 HTTP 服务。教师脚本测试需要 IPv4、IPv6 和空闲的 8080 端口；端口被占用或地址不可用时，该项会标为跳过。

字符统计工具计算后门文件全文中的 `(`、`:`、`,`，包括字符串和注释。当前合计 **47** 个，测试会检查字符预算。

## 使用约定与常见问题

- **浏览器或 `curl --digest` 无法直接使用原始密码登录**：课程密码文件只保存 `SHA256(password)`，配套客户端会先预哈希，再执行 Digest 计算。请使用本项目客户端；这一步与直接使用原密码的普通 Digest 客户端不同。
- **找不到 `passwords.txt`**：在 `py-http-server-main` 目录执行账户初始化命令，并从该目录启动服务器。
- **端口被占用**：关闭另一个服务器实例后再启动。脚本监听 `127.0.0.1:8080` 和 `[::1]:8080`。
- **找不到 `urllib3`**：确认当前终端已激活 `.venv`，并在该环境安装依赖。
- **改了密码但认证结果没变**：重启服务器，使账户文件重新加载。

## 主要文件

| 文件 | 用途 |
| --- | --- |
| [digest_auth.py](py-http-server-main/py_http_server/middlewares/digest_auth.py) | 安全版认证中间件。 |
| [digest_auth_subverted.py](py-http-server-main/py_http_server/middlewares/digest_auth_subverted.py) | 后门版认证中间件，可独立集成到基础服务器。 |
| [client.py](py-http-server-main/client.py) | 正常认证客户端及共用的 HTTP 传输。 |
| [client_subverted.py](py-http-server-main/client_subverted.py) | 后门版客户端，默认正常认证，使用 `--backdoor` 触发演示。 |
| [tests/](py-http-server-main/tests/) | 自动化测试。 |
| [PART1_运行说明.md](py-http-server-main/PART1_运行说明.md) | 详细协议、环境和验证说明。 |
| [基础服务器 README](py-http-server-main/README.md) | 原服务器的路由与中间件文档。 |

课程报告和最终提交 ZIP 暂未生成。本仓库用于开发与运行；最终提交内容仍按课程要求单独整理。
