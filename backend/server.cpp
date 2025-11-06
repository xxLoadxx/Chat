// 自研最小 HTTP 服务器（原生 socket）
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#endif

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <chrono>
#include <thread>
#include <atomic>
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <condition_variable>
#include <fstream>

// 极简 JSON 工具：仅支持本项目所需的功能
static std::string jsonEscape(const std::string &s){
    std::string o; o.reserve(s.size()+8);
    for (char c: s){
        switch(c){
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) { char buf[7]; snprintf(buf,sizeof(buf),"\\u%04x", (unsigned char)c); o += buf; }
                else o += c; break;
        }
    }
    return o;
}

// 仅解析形如 {"k":"v", ...} 的扁平字符串对象（忽略转义的复杂情况）
static std::unordered_map<std::string,std::string> parseJsonFlatStringObject(const std::string &body){
    std::unordered_map<std::string,std::string> kv;
    enum S{INIT, KEY, COLON, VALUE, COMMA, DONE}; S st=INIT;
    std::string key, val; bool inStr=false; bool readingKey=false; bool readingVal=false; bool esc=false;
    for (size_t i=0;i<body.size();++i){ char c=body[i];
        if (st==INIT){ if (c=='{') { st=KEY; } }
        else if (st==KEY){ if (!inStr){ if (c=='"'){ inStr=true; readingKey=true; key.clear(); } else if (c=='}'){ st=DONE; break; } }
            else { if (esc){ key.push_back(c); esc=false; }
                   else if (c=='\\'){ esc=true; }
                   else if (c=='"'){ inStr=false; st=COLON; }
                   else key.push_back(c); }
        }
        else if (st==COLON){ if (c==':'){ st=VALUE; } }
        else if (st==VALUE){ if (!inStr){ if (c=='"'){ inStr=true; readingVal=true; val.clear(); }
                                             else if (c=='}'){ if(!key.empty()) kv[key]=""; st=DONE; break; } }
            else { if (esc){ val.push_back(c); esc=false; }
                   else if (c=='\\'){ esc=true; }
                   else if (c=='"'){ inStr=false; kv[key]=val; st=COMMA; }
                   else val.push_back(c); }
        }
        else if (st==COMMA){ if (c==',') st=KEY; else if (c=='}'){ st=DONE; break; } }
    }
    return kv;
}

namespace net {
    static void platformInit() {
#ifdef _WIN32
        WSADATA wsaData; WSAStartup(MAKEWORD(2,2), &wsaData);
#else
        signal(SIGPIPE, SIG_IGN);
#endif
    }
    static void platformCleanup() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
    static int closeSocket(int fd) {
#ifdef _WIN32
        return closesocket(fd);
#else
        return close(fd);
#endif
    }
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::string query;
    std::unordered_map<std::string,std::string> headers;
    std::string body;
    std::string header(const std::string &k) const {
        auto it = headers.find(k); if (it==headers.end()) return ""; return it->second;
    }
    std::string queryParam(const std::string &key) const {
        // 朴素解析 ?a=1&b=2
        std::string q = query;
        size_t pos = 0;
        while (pos < q.size()) {
            size_t amp = q.find('&', pos); if (amp == std::string::npos) amp = q.size();
            auto kv = q.substr(pos, amp-pos);
            size_t eq = kv.find('=');
            if (eq != std::string::npos) {
                auto k = kv.substr(0, eq);
                auto v = kv.substr(eq+1);
                if (k == key) return v;
            } else {
                if (kv == key) return "";
            }
            pos = amp + 1;
        }
        return "";
    }
};

struct HttpResponse {
    int status = 200;
    std::vector<std::pair<std::string,std::string>> headers {{"Content-Type","text/plain; charset=utf-8"}};
    std::string body;
    void setJson(const std::string &jsonText) {
        setHeader("Content-Type","application/json; charset=utf-8");
        body = jsonText;
    }
    void setHeader(const std::string &k, const std::string &v){
        for (auto &p: headers) if (p.first==k){ p.second=v; return; }
        headers.emplace_back(k,v);
    }
    std::string serialize() const {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << "\r\n";
        for (auto &h: headers) oss << h.first << ": " << h.second << "\r\n";
        oss << "Content-Length: " << body.size() << "\r\n";
        oss << "Connection: close\r\n\r\n";
        oss << body;
        return oss.str();
    }
};

static bool ieqPrefix(const std::string &s, const std::string &prefix){
    if (s.size() < prefix.size()) return false;
    for (size_t i=0;i<prefix.size();++i) if (tolower(s[i])!=tolower(prefix[i])) return false; return true;
}

static bool readLine(int fd, std::string &out) {
    out.clear(); char c; bool got=false; while (true) {
        int n = recv(fd, &c, 1, 0); if (n<=0) return got; got=true; if (c=='\r') { char n2; int r=recv(fd,&n2,1,MSG_PEEK); if(r>0 && n2=='\n'){ recv(fd,&n2,1,0); } break; } if (c=='\n') break; out.push_back(c);
    } return true;
}

static bool readN(int fd, size_t n, std::string &out){
    out.resize(n); size_t off=0; while (off<n) { int r = recv(fd, &out[off], (int)(n-off), 0); if (r<=0) return false; off += (size_t)r; } return true;
}

static bool parseRequest(int fd, HttpRequest &req) {
    std::string line; if (!readLine(fd, line)) return false; // 请求行
    // 例如: GET /path?x=1 HTTP/1.1
    std::istringstream iss(line); std::string url, proto; if (!(iss >> req.method >> url >> proto)) return false;
    // 拆分 path 与 query
    size_t qpos = url.find('?');
    if (qpos==std::string::npos) { req.path = url; req.query=""; } else { req.path = url.substr(0,qpos); req.query = url.substr(qpos+1); }

    // 读 header
    while (true) {
        if (!readLine(fd, line)) return false; if (line.empty()) break;
        size_t p = line.find(':'); if (p!=std::string::npos) {
            std::string k = line.substr(0,p);
            std::string v = line.substr(p+1);
            // 去除前导空格
            while (!v.empty() && (v[0]==' '||v[0]=='\t')) v.erase(v.begin());
            req.headers[k] = v;
        }
    }
    // 读 body
    size_t cl = 0; if (auto it=req.headers.find("Content-Length"); it!=req.headers.end()) { cl = (size_t) std::stoul(it->second); }
    if (cl>0) { std::string body; if (!readN(fd, cl, body)) return false; req.body.swap(body); }
    return true;
}

static void sendAll(int fd, const std::string &data){ size_t off=0; while (off < data.size()) { int n = send(fd, data.data()+off, (int)(data.size()-off), 0); if (n<=0) break; off += (size_t)n; } }

struct Message {
    uint64_t seq;
    std::string fromUser;
    std::string toUser;
    std::string text;
    int64_t timestampMs;
};

struct UserSession {
    std::string username;
};

class ChatStore {
public:
    bool registerUser(const std::string &username, const std::string &password) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        if (users_.count(username)) return false;
        users_[username] = password;
        return true;
    }

    bool login(const std::string &username, const std::string &password, std::string &outToken) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        auto it = users_.find(username);
        if (it == users_.end() || it->second != password) return false;
        // 简易 token：username + 时间戳（演示用）
        outToken = username + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        sessions_[outToken] = UserSession{username};
        return true;
    }

    std::optional<UserSession> auth(const std::string &token) {
        std::shared_lock<std::shared_mutex> lock(mu_);
        auto it = sessions_.find(token);
        if (it == sessions_.end()) return std::nullopt;
        return it->second;
    }

    std::vector<std::string> contacts(const std::string &me) {
        std::shared_lock<std::shared_mutex> lock(mu_);
        std::vector<std::string> res;
        res.reserve(users_.size());
        for (auto &kv : users_) {
            if (kv.first != me) res.push_back(kv.first);
        }
        std::sort(res.begin(), res.end());
        return res;
    }

    uint64_t sendMessage(const std::string &from, const std::string &to, const std::string &text) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        uint64_t seq = ++seqCounter_;
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        messages_.push_back(Message{seq, from, to, text, now});
        cv_.notify_all();
        return seq;
    }

    // 拉取与某个对端的消息（双向对话）
    std::vector<Message> getMessages(const std::string &me, const std::string &with, uint64_t since) {
        std::shared_lock<std::shared_mutex> lock(mu_);
        std::vector<Message> res;
        for (auto &m : messages_) {
            if (m.seq <= since) continue;
            bool isPair = (m.fromUser == me && m.toUser == with) || (m.fromUser == with && m.toUser == me);
            if (isPair) res.push_back(m);
        }
        std::sort(res.begin(), res.end(), [](const Message &a, const Message &b){ return a.seq < b.seq; });
        return res;
    }

    // 长轮询等待新消息（最多阻塞 waitMs 毫秒）返回是否有新消息
    bool waitForNew(uint64_t lastSeenSeq, int waitMs) {
        std::unique_lock<std::shared_mutex> lock(mu_);
        if (seqCounter_ > lastSeenSeq) return true;
        if (waitMs <= 0) return false;
        return cv_.wait_for(lock, std::chrono::milliseconds(waitMs), [&]{ return seqCounter_ > lastSeenSeq; });
    }

private:
    std::shared_mutex mu_;
    std::unordered_map<std::string, std::string> users_;
    std::unordered_map<std::string, UserSession> sessions_;
    std::vector<Message> messages_;
    std::condition_variable_any cv_;
    uint64_t seqCounter_ = 0;
};

static ChatStore g_store;

static std::optional<std::string> parseBearer(const HttpRequest &req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return std::nullopt;
    const auto &v = it->second;
    std::string prefix = "Bearer ";
    if (v.rfind(prefix, 0) == 0) return v.substr(prefix.size());
    return std::nullopt;
}

static void jsonResponseRaw(HttpResponse &res, int status, const std::string &jsonText) {
    res.status = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.body = jsonText;
}

// 处理一个连接
static void handleClient(int cfd, const std::string &staticRoot) {
    HttpRequest req; HttpResponse res;
    if (!parseRequest(cfd, req)) { net::closeSocket(cfd); return; }

    auto notFound = [&](){ res.status=404; res.setHeader("Content-Type","text/plain; charset=utf-8"); res.body = "Not Found"; };
    auto badReq = [&](const std::string &msg){ jsonResponseRaw(res, 400, std::string("{\"error\":\"") + jsonEscape(msg) + "\"}"); };

    // API 路由
    if (req.path.rfind("/api/", 0) == 0) {
        if (req.path == "/api/register" && req.method == "POST") {
            auto kv = parseJsonFlatStringObject(req.body);
            std::string username = kv["username"];
            std::string password = kv["password"];
            if (username.empty() || password.empty()) return (void)jsonResponseRaw(res, 400, "{\"error\":\"用户名与密码必填\"}");
            if (!g_store.registerUser(username, password)) return (void)jsonResponseRaw(res, 409, "{\"error\":\"用户已存在\"}");
            return (void)jsonResponseRaw(res, 200, "{\"ok\":true}");
        }
        if (req.path == "/api/login" && req.method == "POST") {
            auto kv = parseJsonFlatStringObject(req.body);
            std::string username = kv["username"];
            std::string password = kv["password"];
            std::string token;
            if (!g_store.login(username, password, token)) return (void)jsonResponseRaw(res, 401, "{\"error\":\"用户名或密码错误\"}");
            std::string js = std::string("{\"token\":\"") + jsonEscape(token) + "\",\"username\":\"" + jsonEscape(username) + "\"}";
            return (void)jsonResponseRaw(res, 200, js);
        }
        if (req.path == "/api/contacts" && req.method == "GET") {
            auto token = parseBearer(req); if (!token) return (void)jsonResponseRaw(res, 401, "{\"error\":\"未授权\"}");
            auto session = g_store.auth(*token); if (!session) return (void)jsonResponseRaw(res, 401, "{\"error\":\"会话无效\"}");
            auto list = g_store.contacts(session->username);
            std::string js = "{\"contacts\":[";
            for (size_t i=0;i<list.size();++i){ if(i) js+=","; js += "\"" + jsonEscape(list[i]) + "\""; }
            js += "]}";
            return (void)jsonResponseRaw(res, 200, js);
        }
        if (req.path == "/api/send" && req.method == "POST") {
            auto token = parseBearer(req); if (!token) return (void)jsonResponseRaw(res, 401, "{\"error\":\"未授权\"}");
            auto session = g_store.auth(*token); if (!session) return (void)jsonResponseRaw(res, 401, "{\"error\":\"会话无效\"}");
            auto kv = parseJsonFlatStringObject(req.body);
            std::string to = kv["to"];
            std::string text = kv["text"];
            if (to.empty() || text.empty()) return (void)jsonResponseRaw(res, 400, "{\"error\":\"参数缺失\"}");
            uint64_t seq = g_store.sendMessage(session->username, to, text);
            std::string js = std::string("{\"ok\":true,\"seq\":") + std::to_string(seq) + "}";
            return (void)jsonResponseRaw(res, 200, js);
        }
        if (req.path == "/api/messages" && req.method == "GET") {
            auto token = parseBearer(req); if (!token) return (void)jsonResponseRaw(res, 401, "{\"error\":\"未授权\"}");
            auto session = g_store.auth(*token); if (!session) return (void)jsonResponseRaw(res, 401, "{\"error\":\"会话无效\"}");
            auto withIt = req.queryParam("with"); if (withIt.empty()) return (void)jsonResponseRaw(res, 400, "{\"error\":\"缺少 with 参数\"}");
            uint64_t since = 0; try { auto s = req.queryParam("since"); if(!s.empty()) since = std::stoull(s); } catch(...) {}
            int wait = 0; try { auto w = req.queryParam("wait"); if(!w.empty()) wait = std::stoi(w); } catch(...) {}
            if (wait > 0) { g_store.waitForNew(since, std::min(wait, 25000)); }
            auto msgs = g_store.getMessages(session->username, withIt, since);
            uint64_t latest = since;
            std::string js = "{\"messages\":[";
            for (size_t i=0;i<msgs.size();++i){
                auto &m = msgs[i]; if (i) js += ",";
                js += "{\"seq\":" + std::to_string(m.seq)
                    + ",\"from\":\"" + jsonEscape(m.fromUser) + "\""
                    + ",\"to\":\"" + jsonEscape(m.toUser) + "\""
                    + ",\"text\":\"" + jsonEscape(m.text) + "\""
                    + ",\"ts\":" + std::to_string(m.timestampMs) + "}";
                latest = std::max(latest, m.seq);
            }
            js += "],\"latest\":" + std::to_string(latest) + "}";
            return (void)jsonResponseRaw(res, 200, js);
        }
        if (req.path == "/api/health" && req.method == "GET") {
            return (void)jsonResponseRaw(res, 200, "{\"ok\":true}");
        }
        notFound();
    } else {
        // 静态文件
        std::string rel = req.path;
        if (rel == "/") rel = "/index.html";
        std::filesystem::path p = std::filesystem::path(staticRoot) / rel.substr(1);
        if (!std::filesystem::exists(p) || std::filesystem::is_directory(p)) {
            res.status = 404; res.body = "Not Found"; res.setHeader("Content-Type","text/plain; charset=utf-8");
        } else {
            std::ifstream ifs(p, std::ios::binary);
            std::ostringstream oss; oss << ifs.rdbuf();
            res.body = oss.str();
            std::string ctype = "text/plain";
            if (p.extension()==".html") ctype="text/html; charset=utf-8";
            else if (p.extension()==".css") ctype="text/css; charset=utf-8";
            else if (p.extension()==".js") ctype="application/javascript; charset=utf-8";
            else if (p.extension()==".png") ctype="image/png";
            else if (p.extension()==".jpg"||p.extension()==".jpeg") ctype="image/jpeg";
            res.setHeader("Content-Type", ctype);
        }
    }

    auto data = res.serialize();
    sendAll(cfd, data);
    net::closeSocket(cfd);
}

int main() {
    net::platformInit();

    // 预置一些用户（便于测试）
    g_store.registerUser("alice", "123456");
    g_store.registerUser("bob", "123456");

    std::string staticRoot = "./frontend";
    if (!std::filesystem::exists(staticRoot)) staticRoot = "../frontend";

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return 1;
    int yes=1;
#ifdef _WIN32
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#else
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(8080); addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sfd, (sockaddr*)&addr, sizeof(addr))<0) return 2;
    if (listen(sfd, 128)<0) return 3;

    while (true) {
        sockaddr_in caddr{}; socklen_t clen = sizeof(caddr);
        int cfd = accept(sfd, (sockaddr*)&caddr, &clen);
        if (cfd < 0) continue;
        std::thread([cfd, staticRoot]{ handleClient(cfd, staticRoot); }).detach();
    }

    net::closeSocket(sfd);
    net::platformCleanup();
    return 0;
}


