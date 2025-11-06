Chat – 简易网页聊天（前端 + C++ 后端）

目录结构

```
backend/           C++ 服务（CMake 构建，基于 cpp-httplib）
frontend/          前端静态页面与脚本
```

功能

- 登录 / 注册（内存存储示例，不持久化）
- 左侧联系人列表，右侧聊天窗口
- 发送消息与长轮询获取新消息（避免 WebSocket 依赖）

构建后端（Windows / macOS / Linux）

1) 进入项目根目录：

```bash
cmake -S backend -B backend/build -DCMAKE_BUILD_TYPE=Release
cmake --build backend/build --config Release
```

2) 运行服务（默认端口 8080）：

在“项目根目录”运行可执行文件（这样能正确挂载 ./frontend）：

```bash
./backend/build/chat_server
```

Windows PowerShell 示例（在项目根目录执行）：

```powershell
cmake -S backend -B backend/build -DCMAKE_BUILD_TYPE=Release
cmake --build backend/build --config Release
./backend/build/Release/chat_server.exe
```

前端访问

后端会把 `frontend/` 目录作为静态资源根目录挂载，启动后直接访问：

```
http://localhost:8080/
```

注意

- 本示例为教学用途，用户/会话/消息均保存在内存中，重启即丢失。
- 未实现密码加盐/哈希与数据库，请勿用于生产环境。
- 已改为原生 socket + 自研最小 HTTP 解析/路由，无需任何网络库。


