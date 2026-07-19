# 壹 介绍server_Tool

有的时候，我们需要在内网环境中传输东西、或者是聊天、或者是做协议探测。例如之前有一次在客户现场，要传东西，然后都没有`U`盘，当时就写了一个简单的`demo`服务器工具，后来想想要不要做一个各种协议或者服务都能探测的服务端，所以就写了这个工具的雏形，后来发现`github`上已经有了一个非常优秀的`http`文件服务工具@[simple-http-server](https://github.com/TheWaWaR/simple-http-server)，引用了其界面（确实很简约且好看），然后自己又加了一个聊天室。

# 貳 功能

- HTTP 文件服务
- 简易聊天室
- FTP 探测/真实文件

# 叁 编译

```bash
# 当前平台
go build -o server_Tool -ldflags="-s -w" -trimpath .

# 交叉编译示例（无需再拷网页资源）
GOOS=linux   GOARCH=amd64 go build -o server_Tool_linux_amd64   -ldflags="-s -w" -trimpath .
GOOS=windows GOARCH=amd64 go build -o server_Tool_windows_amd64.exe -ldflags="-s -w" -trimpath .
GOOS=darwin  GOARCH=amd64 go build -o server_Tool_darwin_amd64  -ldflags="-s -w" -trimpath .

# 需要注意的是MAC存在证书问题，需要输入：codesign --sign - 文件程序名
```

复制到目标机器时**只需复制可执行文件**。

# 肆 使用

## 4.1 参数

| 参数 | 说明 |
|------|------|
| `-p` | 端口（HTTP 默认 10000；FTP 若仍为 10000 则改用 21） |
| `-hn` | 监听 IP |
| `-token` | 访问密钥 |
| `-ul` | 聊天用户，逗号分隔 |
| `-root` | 文件根目录 |
| `-m` | `http` / `ftp` |
| `-ftp-mode` | `probe`（默认，协议探测）/ `real`（真实文件，限 root） |
| `-db` | SQLite 路径（默认 `httpserver_db.db`），用户与聊天消息持久化 |
| `-logflag` / `-outfile` / `-debug` | 日志 |

## 4.2 快速使用

```bash
# 推荐：指定共享目录 + 密钥 + 聊天用户
./server_Tool -p 10000 -root ./share -token "足够长的密钥" -ul alice,bob

# 浏览器打开 http://<IP>:10000
# 1) 设置 userauth（与 -token 一致）
# 2) 文件下载 / 上传 / 聊天室
```

## 4.3 FTP

```bash
# 探测模式（无真实传文件）
./server_Tool -m ftp -ftp-mode probe -p 21

# 真实文件（密码 = -token；无 -token 时任意密码可登录但禁止 STOR）
./server_Tool -m ftp -ftp-mode real -p 21 -root ./share -token "密钥"
```

## 4.4 聊天

- 用户名须在 -ul 列表（或通过「用户设置」添加并已写入数据库）
- 私聊：`@alice:` 或 `@alice,bob:消息内容`
- 用户与最近消息写入 `-db`，重启后用户列表可恢复，进房可拉历史，@ 私聊仅对参与者可见，其他人重进聊天室也看不到
- 用户管理页支持添加/删除用户；删除会写入数据库并踢下线

# 伍 安全建议

- 生产/客户现场务必设置足够长的 -token
- 将 -root 指到专用共享目录，不要指向系统根
- 本工具面向内网应急，请勿直接暴露到公网

# 陆 更新

- v1.3.0：内嵌网页与使用说明、无 `-token` 写保护、SQLite 持久化、FTP probe/real、路径 jail 等
- v1.2.0：稳定性与安全加固
- v1.1.0：初版凑合可用
