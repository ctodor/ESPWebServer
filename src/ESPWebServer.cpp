
// include <Arduino.h> JUSt for loggin, logging won't work without this include
#include <Arduino.h>

#include "ESPWebServer.h"
#include "esp_log.h"
#include "esp_random.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <task.h>

static const char *TAG_WEB = "ESPWebServer";

ESPWebServer *ESPWebServer::_instance = nullptr;

// cookie name pentru sesiune
static const char *SESSION_COOKIE = "esp_session";

// pagina de login returnata automat in modul Session cand userul nu e autentificat
static const char *LOGIN_PAGE =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<title>Login</title>"
    "<style>body{font-family:sans-serif;display:flex;align-items:center;"
    "justify-content:center;height:100vh;margin:0;background:#f5f5f5;}"
    "form{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px #0002;"
    "display:flex;flex-direction:column;gap:1rem;min-width:260px;}"
    "input{padding:.5rem;border:1px solid #ccc;border-radius:4px;font-size:1rem;}"
    "button{padding:.6rem;background:#0066cc;color:#fff;border:none;"
    "border-radius:4px;font-size:1rem;cursor:pointer;}"
    "button:hover{background:#0055aa;}.err{color:#c00;font-size:.9rem;}</style>"
    "</head><body><form method='POST' action='/login'>"
    "<h2 style='margin:0'>Login</h2>"
    "<input name='username' placeholder='Username' required autofocus>"
    "<input name='password' type='password' placeholder='Password' required>"
    "<button type='submit'>Login</button>"
    "%ERR%"
    "</form></body></html>";

// ===========================================================================
// Constructor / Destructor
// ===========================================================================

ESPWebServer::ESPWebServer(uint16_t port, uint8_t maxSockets,
                           uint8_t recvTimeoutSec, uint8_t sendTimeoutSec)
    : _port(port), _maxSockets(maxSockets), _recvTimeout(recvTimeoutSec), _sendTimeout(sendTimeoutSec)
{
    _instance = this;
    ESP_LOGI(TAG_WEB, "ctor");
}

ESPWebServer::~ESPWebServer()
{
    stop();
    if (_instance == this)
        _instance = nullptr;

    ESP_LOGI(TAG_WEB, "dtor");
}

// ===========================================================================
// Configurare autentificare
// ===========================================================================

void ESPWebServer::setCredentials(const std::string &username, const std::string &password)
{
    _username = username;
    _password = password;
    ESP_LOGI(TAG_WEB, "setCredentials");
}

void ESPWebServer::setAuthMode(AuthMode mode)
{
    _authMode = mode;
    _loginRoutes.clear();
    _authExclude.clear();
    ESP_LOGI(TAG_WEB, "setAuthMode:%d", _authMode);

    if (_authMode == AuthMode::Session)
    {
        // excludem /login din verificarea de auth
        _authExclude.insert("/login");

        // POST /login
        RouteEntry loginEntry;
        loginEntry.uriPattern = "/login";
        loginEntry.uriEsp = "/login";
        loginEntry.method = HTTP_POST;
        loginEntry.hasPathArg = false;
        loginEntry.requireAuth = false;
        loginEntry.handler = [this]()
        { _handleLogin(); };
        _loginRoutes.push_back(loginEntry);

        // GET /login — afiseaza formularul
        RouteEntry loginGetEntry;
        loginGetEntry.uriPattern = "/login";
        loginGetEntry.uriEsp = "/login";
        loginGetEntry.method = HTTP_GET;
        loginGetEntry.hasPathArg = false;
        loginGetEntry.requireAuth = false;
        loginGetEntry.handler = [this]()
        {
            std::string page = LOGIN_PAGE;
            size_t pos = page.find("%ERR%");
            if (pos != std::string::npos)
                page.replace(pos, 5, "");
            send(200, "text/html", page);
        };
        _loginRoutes.push_back(loginGetEntry);

        // POST /logout
        RouteEntry logoutEntry;
        logoutEntry.uriPattern = "/logout";
        logoutEntry.uriEsp = "/logout";
        logoutEntry.method = HTTP_POST;
        logoutEntry.hasPathArg = false;
        logoutEntry.requireAuth = false;
        logoutEntry.handler = [this](){ _handleLogout(); };
        _loginRoutes.push_back(logoutEntry);
    }
}

void ESPWebServer::setAuthRequired(bool required)
{
    _authRequired = required;
    ESP_LOGI(TAG_WEB, "setAuthRequired");
}

void ESPWebServer::setAuthExclude(const std::vector<std::string> &paths)
{
    _authExclude.clear();
    for (auto &p : paths)
        _authExclude.insert(p);

    ESP_LOGI(TAG_WEB, "setAuthExclude");
}

void ESPWebServer::setSessionTimeout(uint32_t seconds)
{
    _sessionTimeout = seconds;
    ESP_LOGI(TAG_WEB, "setSessionTimeout");
}

// ===========================================================================
// Inregistrare rute
// ===========================================================================

void ESPWebServer::on(const std::string &path, WebHandler0 handler)
{
    on(path, HTTP_GET, std::move(handler));
}

void ESPWebServer::on(const std::string &path, http_method method, WebHandler0 handler)
{
    RouteEntry entry;
    entry.uriPattern = path;
    entry.uriEsp = _translateUri(path, entry.hasPathArg);
    entry.method = method;
    entry.handler = std::move(handler);
    entry.requireAuth = _authRequired;
    _routes.push_back(std::move(entry));
}

void ESPWebServer::onNotFound(WebHandler0 handler)
{
    _notFoundHandler = std::move(handler);
}

// ===========================================================================
// Ciclu de viata
// ===========================================================================

bool ESPWebServer::start()
{
    if (_server != nullptr)
    {
        ESP_LOGW(TAG_WEB, "Server already running on port %d", _port);
        return true;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = _port;
    config.max_open_sockets = _maxSockets;
    config.recv_wait_timeout = _recvTimeout;
    config.send_wait_timeout = _sendTimeout;
    config.lru_purge_enable = true;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 20;
    config.stack_size = 16000;

    esp_err_t err = httpd_start(&_server, &config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG_WEB, "httpd_start failed: %s", esp_err_to_name(err));
        _server = nullptr;
        return false;
    }

    _registerRoutes();
    ESP_LOGI(TAG_WEB, "Started on port %d, auth=%s, routes=%zu",
             _port,
             _authMode == AuthMode::Basic ? "Basic" : _authMode == AuthMode::Session ? "Session"
                                                                                     : "None",
             _routes.size());
    return true;
}

void ESPWebServer::stop()
{
    if (_server == nullptr)
        return;
    
    ESP_LOGI(TAG_WEB, "Try Stop");
    httpd_stop(_server);
    _server = nullptr;
    vTaskDelay(pdMS_TO_TICKS(10));
    _killHttpdZombieTasks();
    ESP_LOGI(TAG_WEB, "Stopped");
}

bool ESPWebServer::restart()
{
    stop();
    return start();
}

bool ESPWebServer::isRunning() const
{
    return _server != nullptr;
}

// ===========================================================================
// API request
// ===========================================================================

void ESPWebServer::send(int code, const char *contentType, const std::string &body)
{
    if (!_current.req)
        return;
    httpd_resp_set_status(_current.req, _codeToStatus(code));
    httpd_resp_set_type(_current.req, contentType);
    httpd_resp_send(_current.req, body.c_str(), (ssize_t)body.length());
}

void ESPWebServer::send(int code, const char *contentType, const char *body, size_t len)
{
    if (!_current.req)
        return;
    httpd_resp_set_status(_current.req, _codeToStatus(code));
    httpd_resp_set_type(_current.req, contentType);
    httpd_resp_send(_current.req, body, (ssize_t)len);
}

std::string ESPWebServer::arg(const std::string &name) const
{
    auto it = _current.params.find(name);
    return it != _current.params.end() ? it->second : "";
}

size_t ESPWebServer::args() const
{
    return _current.params.size();
}

std::string ESPWebServer::arg(size_t index) const
{
    if (index >= _current.params.size())
        return "";
    auto it = _current.params.begin();
    std::advance(it, index);
    return it->second;
}

std::string ESPWebServer::argName(size_t index) const
{
    if (index >= _current.params.size())
        return "";
    auto it = _current.params.begin();
    std::advance(it, index);
    return it->first;
}

bool ESPWebServer::hasArg(const std::string &name) const
{
    return _current.params.find(name) != _current.params.end();
}

std::string ESPWebServer::uri() const { return _current.uri; }
http_method ESPWebServer::method() const { return _current.method; }
const std::string &ESPWebServer::body() const { return _current.body; }
bool ESPWebServer::isAuthenticated() const { return _current.authenticated; }

std::string ESPWebServer::pathArg(uint8_t index) const
{
    return index < _current.pathArgs.size() ? _current.pathArgs[index] : "";
}

std::string ESPWebServer::header(const std::string &name) const
{
    if (!_current.req)
        return "";
    size_t len = httpd_req_get_hdr_value_len(_current.req, name.c_str());
    if (len == 0)
        return "";
    char *buf = new char[len + 1];
    httpd_req_get_hdr_value_str(_current.req, name.c_str(), buf, len + 1);
    std::string val(buf, len);
    delete[] buf;
    return val;
}

void ESPWebServer::sendHeader(const std::string &name, const std::string &value)
{
    if (_current.req)
        httpd_resp_set_hdr(_current.req, name.c_str(), value.c_str());
}

void ESPWebServer::beginChunked(int code, const char *contentType)
{
    if (!_current.req)
        return;
    httpd_resp_set_status(_current.req, _codeToStatus(code));
    httpd_resp_set_type(_current.req, contentType);
    _current.chunkedActive = true;
}

void ESPWebServer::sendContent(const std::string &chunk)
{
    if (!_current.req)
        return;
    if (chunk.empty())
    {
        httpd_resp_send_chunk(_current.req, nullptr, 0);
        _current.chunkedActive = false;
        return;
    }
    httpd_resp_send_chunk(_current.req, chunk.c_str(), (ssize_t)chunk.length());
}

void ESPWebServer::sendContent(const char *chunk, size_t len)
{
    if (!_current.req)
        return;
    if (len == 0)
    {
        httpd_resp_send_chunk(_current.req, nullptr, 0);
        _current.chunkedActive = false;
        return;
    }
    httpd_resp_send_chunk(_current.req, chunk, (ssize_t)len);
}

void ESPWebServer::endChunked()
{
    if (!_current.req)
        return;
    httpd_resp_send_chunk(_current.req, nullptr, 0);
    _current.chunkedActive = false;
}

// ===========================================================================
// Autentificare — logica principala
// ===========================================================================

bool ESPWebServer::_checkAuth(httpd_req_t *req)
{
    if (_authMode == AuthMode::None)
        return true;

    // extrage uri fara query string
    std::string fullUri(req->uri);
    size_t qpos = fullUri.find('?');
    std::string reqUri = (qpos != std::string::npos) ? fullUri.substr(0, qpos) : fullUri;

    if (_isExcluded(reqUri))
        return true;

    switch (_authMode)
    {
    case AuthMode::Basic:
        return _checkBasicAuth(req);
    case AuthMode::Session:
        return _checkSessionAuth(req);
    default:
        return true;
    }
}

bool ESPWebServer::_checkBasicAuth(httpd_req_t *req)
{
    size_t len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (len == 0)
        return false;

    char *buf = new char[len + 1];
    httpd_req_get_hdr_value_str(req, "Authorization", buf, len + 1);
    std::string authHeader(buf, len);
    delete[] buf;

    // format: "Basic <base64(user:pass)>"
    const std::string prefix = "Basic ";
    if (authHeader.substr(0, prefix.size()) != prefix)
        return false;

    std::string decoded = _base64Decode(authHeader.substr(prefix.size()));
    size_t colon = decoded.find(':');
    if (colon == std::string::npos)
        return false;

    std::string user = decoded.substr(0, colon);
    std::string pass = decoded.substr(colon + 1);

    return user == _username && pass == _password;
}

bool ESPWebServer::_checkSessionAuth(httpd_req_t *req)
{
    std::string token = _getCookie(req, SESSION_COOKIE);
    if (token.empty())
        return false;

    auto it = _sessions.find(token);
    if (it == _sessions.end())
        return false;

    // verifica expirare
    if (_now() > it->second)
    {
        _sessions.erase(it);
        ESP_LOGD(TAG_WEB, "Session expired: %s", token.substr(0, 8).c_str());
        return false;
    }

    return true;
}

void ESPWebServer::_sendUnauthorized(httpd_req_t *req)
{
    ESP_LOGI(TAG_WEB, "_sendUnauthorized called, mode=%d", (int)_authMode);
    if (_authMode == AuthMode::Basic)
    {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32\"");
        httpd_resp_send(req, "Unauthorized", 12);
    }
    else
    {
        // Session: redirect la /login
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_send(req, nullptr, 0);
    }
}

bool ESPWebServer::_isExcluded(const std::string &uri) const
{
    return _authExclude.find(uri) != _authExclude.end();
}

void ESPWebServer::_handleLogin()
{
    std::string user = arg("username");
    std::string pass = arg("password");

    if (user == _username && pass == _password)
    {
        std::string token = _generateToken();
        _sessions[token] = _now() + _sessionTimeout;

        // seteaza cookie HttpOnly cu expirare
        std::string cookie = std::string(SESSION_COOKIE) + "=" + token +
                             "; HttpOnly; Path=/; Max-Age=" +
                             std::to_string(_sessionTimeout);
        httpd_resp_set_hdr(_current.req, "Set-Cookie", cookie.c_str());
        httpd_resp_set_status(_current.req, "302 Found");
        httpd_resp_set_hdr(_current.req, "Location", "/");
        httpd_resp_send(_current.req, nullptr, 0);

        ESP_LOGI(TAG_WEB, "Login OK for user '%s'", user.c_str());
    }
    else
    {
        // login gresit — afiseaza formularul cu mesaj de eroare
        std::string page = LOGIN_PAGE;
        size_t pos = page.find("%ERR%");
        const std::string errMsg = "<p class='err'>Username sau parola incorecte.</p>";
        if (pos != std::string::npos)
            page.replace(pos, 5, errMsg);

        ESP_LOGW(TAG_WEB, "Login FAIL for user '%s'", user.c_str());
        send(401, "text/html", page);
    }
}

void ESPWebServer::_handleLogout()
{
    std::string token = _getCookie(_current.req, SESSION_COOKIE);
    if (!token.empty())
    {
        _sessions.erase(token);
        ESP_LOGI(TAG_WEB, "Logout: session removed");
    }

    // sterge cookie
    std::string cookie = std::string(SESSION_COOKIE) +
                         "=; HttpOnly; Path=/; Max-Age=0";
    httpd_resp_set_hdr(_current.req, "Set-Cookie", cookie.c_str());
    httpd_resp_set_status(_current.req, "302 Found");
    httpd_resp_set_hdr(_current.req, "Location", "/login");
    httpd_resp_send(_current.req, nullptr, 0);
}

std::string ESPWebServer::_generateToken() const
{
    // 32 bytes random -> hex string de 64 caractere
    uint8_t buf[32];
    esp_fill_random(buf, sizeof(buf));
    std::ostringstream oss;
    for (auto b : buf)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

std::string ESPWebServer::_getCookie(httpd_req_t *req, const std::string &name) const
{
    size_t len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (len == 0)
        return "";

    char *buf = new char[len + 1];
    httpd_req_get_hdr_value_str(req, "Cookie", buf, len + 1);
    std::string cookies(buf, len);
    delete[] buf;

    // cauta "name=value" in sirul de cookies
    std::string search = name + "=";
    size_t pos = cookies.find(search);
    if (pos == std::string::npos)
        return "";

    pos += search.size();
    size_t end = cookies.find(';', pos);
    return cookies.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

uint32_t ESPWebServer::_now() const
{
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

// ===========================================================================
// Dispatch
// ===========================================================================

void ESPWebServer::_registerRoutes()
{
    std::vector<RouteEntry> allRoutes = _routes;
    allRoutes.insert(allRoutes.end(), _loginRoutes.begin(), _loginRoutes.end());

    size_t count = allRoutes.size();
    ESP_LOGI(TAG_WEB, "Register routes, count:%d",count);

    for (size_t i = 0; i < count ; ++i)
    {
        httpd_uri_t uri = {};
        const char* uriEsp = allRoutes[i].uriEsp.c_str();
        ESP_LOGI(TAG_WEB, "Register route: %s",uriEsp);
        uri.uri = uriEsp;
        uri.method = allRoutes[i].method;
        uri.handler = _dispatch;
        uri.user_ctx = reinterpret_cast<void *>(i);

        esp_err_t err = httpd_register_uri_handler(_server, &uri);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG_WEB, "Failed to register %s: %s", allRoutes[i].uriPattern.c_str(), esp_err_to_name(err));
        }
            
    }

    httpd_register_err_handler(_server, HTTPD_404_NOT_FOUND, _handle404);

    if (_otaEnabled)
    {
        httpd_uri_t otaUri = {};
        otaUri.uri = _otaPath.c_str();
        otaUri.method = HTTP_POST;
        otaUri.handler = _dispatchOta;
        otaUri.user_ctx = nullptr;
        esp_err_t err = httpd_register_uri_handler(_server, &otaUri);
        if (err != ESP_OK)
            ESP_LOGE(TAG_WEB, "Failed to register OTA route %s: %s", _otaPath.c_str(), esp_err_to_name(err));
        else
            ESP_LOGI(TAG_WEB, "OTA enabled at POST %s", _otaPath.c_str());

        // GET /ota — pagina HTML de upload
        // derivam path-ul paginii din path-ul de upload: /ota/update -> /ota
        std::string pagePath = _otaPath.substr(0, _otaPath.rfind('/'));
        if (pagePath.empty())
            pagePath = "/ota";
        _otaPagePath = pagePath;

        httpd_uri_t pageUri = {};
        pageUri.uri = _otaPagePath.c_str();
        pageUri.method = HTTP_GET;
        pageUri.handler = _dispatchOtaPage;
        pageUri.user_ctx = nullptr;
        err = httpd_register_uri_handler(_server, &pageUri);
        if (err != ESP_OK)
            ESP_LOGE(TAG_WEB, "Failed to register OTA page route %s: %s", _otaPagePath.c_str(), esp_err_to_name(err));

        // GET /ota/info — informatii firmware curent (JSON)
        _otaInfoPath = pagePath + "/info";
        httpd_uri_t infoUri = {};
        infoUri.uri = _otaInfoPath.c_str();
        infoUri.method = HTTP_GET;
        infoUri.handler = _dispatchOtaInfo;
        infoUri.user_ctx = nullptr;
        err = httpd_register_uri_handler(_server, &infoUri);
        if (err != ESP_OK)
            ESP_LOGE(TAG_WEB, "Failed to register OTA info route %s: %s", _otaInfoPath.c_str(), esp_err_to_name(err));
        ESP_LOGI(TAG_WEB, "OTA page at GET %s, info at GET %s", _otaPagePath.c_str(), _otaInfoPath.c_str());
    }
}

void ESPWebServer::_populateCurrent(httpd_req_t *req, const RouteEntry &route)
{
    _current.req = req;
    _current.method = (http_method)req->method;
    _current.authenticated = false;
    _current.chunkedActive = false;
    _current.body.clear();
    _current.params.clear();
    _current.pathArgs.clear();

    std::string fullUri(req->uri);
    size_t qpos = fullUri.find('?');
    _current.uri = (qpos != std::string::npos) ? fullUri.substr(0, qpos) : fullUri;

    if (req->content_len > 0)
    {
        char *buf = new char[req->content_len];
        int received = httpd_req_recv(req, buf, req->content_len);
        if (received > 0)
            _current.body.assign(buf, (size_t)received);
        delete[] buf;
    }

    _current.params = _parseParams(req, _current.body);

    if (route.hasPathArg)
        _current.pathArgs = _extractPathArgs(route.uriPattern, _current.uri);
}

esp_err_t ESPWebServer::_dispatch(httpd_req_t *req)
{
    if (!_instance)
        return ESP_FAIL;

    size_t routeIndex = reinterpret_cast<size_t>(req->user_ctx);
    if (routeIndex >= _instance->_routes.size())
        return ESP_FAIL;

    const RouteEntry &route = _instance->_routes[routeIndex];
    _instance->_populateCurrent(req, route);

    ets_printf(TAG_WEB, "dispatch uri=%s authRequired=%d authMode=%d",
               _instance->_current.uri.c_str(),
               (int)_instance->_authRequired,
               (int)_instance->_authMode);

    // verifica autentificare
    if (_instance->_authRequired || route.requireAuth)
    {
        bool ok = _instance->_checkAuth(req);
        _instance->_current.authenticated = ok;
        if (!ok)
        {
            _instance->_sendUnauthorized(req);
            return ESP_OK;
        }
    }

    route.handler();
    return ESP_OK;
}

esp_err_t ESPWebServer::_handle404(httpd_req_t *req, httpd_err_code_t)
{
    if (!_instance)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
        return ESP_FAIL;
    }

    RouteEntry dummy{};
    dummy.hasPathArg = false;
    dummy.requireAuth = false;
    _instance->_populateCurrent(req, dummy);

    if (_instance->_authRequired)
    {
        bool ok = _instance->_checkAuth(req);
        _instance->_current.authenticated = ok;
        if (!ok)
        {
            _instance->_sendUnauthorized(req);
            return ESP_FAIL;
        }
    }

    if (_instance->_notFoundHandler)
        _instance->_notFoundHandler();
    else
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");

    return ESP_FAIL;
}

// ===========================================================================
// Parsare parametri
// ===========================================================================

std::map<std::string, std::string> ESPWebServer::_parseParams(httpd_req_t *req,
                                                              const std::string &body)
{
    std::map<std::string, std::string> result;

    size_t qLen = httpd_req_get_url_query_len(req);
    if (qLen > 0)
    {
        char *buf = new char[qLen + 1];
        if (httpd_req_get_url_query_str(req, buf, qLen + 1) == ESP_OK)
        {
            std::string qs(buf, qLen);
            _parseFormEncoded(qs, result);
        }
        delete[] buf;
    }

    if (!body.empty())
    {
        size_t ctLen = httpd_req_get_hdr_value_len(req, "Content-Type");
        if (ctLen > 0)
        {
            char *ct = new char[ctLen + 1];
            httpd_req_get_hdr_value_str(req, "Content-Type", ct, ctLen + 1);
            std::string ctStr(ct, ctLen);
            delete[] ct;
            if (ctStr.find("application/x-www-form-urlencoded") != std::string::npos)
                _parseFormEncoded(body, result);
        }
    }

    return result;
}

void ESPWebServer::_parseFormEncoded(const std::string &data,
                                     std::map<std::string, std::string> &out)
{
    size_t start = 0;
    while (start < data.size())
    {
        size_t amp = data.find('&', start);
        size_t end = (amp == std::string::npos) ? data.size() : amp;
        std::string pair = data.substr(start, end - start);

        size_t eq = pair.find('=');
        if (eq != std::string::npos)
        {
            std::string key = pair.substr(0, eq);
            std::string val = pair.substr(eq + 1);
            _urlDecode(key);
            _urlDecode(val);
            out[key] = val;
        }

        if (amp == std::string::npos)
            break;
        start = amp + 1;
    }
}

// ===========================================================================
// URI template
// ===========================================================================

std::string ESPWebServer::_translateUri(const std::string &pattern, bool &hasPathArg)
{
    hasPathArg = false;
    std::string result;
    result.reserve(pattern.size());

    size_t i = 0;
    while (i < pattern.size())
    {
        if (pattern[i] == '{')
        {
            size_t close = pattern.find('}', i);
            if (close != std::string::npos)
            {
                result += '*';
                hasPathArg = true;
                i = close + 1;
                continue;
            }
        }
        result += pattern[i++];
    }
    return result;
}

std::vector<std::string> ESPWebServer::_extractPathArgs(const std::string &pattern,
                                                        const std::string &actualUri)
{
    std::vector<std::string> args;

    auto split = [](const std::string &s, char delim)
    {
        std::vector<std::string> tokens;
        size_t start = 0;
        while (start < s.size())
        {
            size_t pos = s.find(delim, start);
            if (pos == std::string::npos)
                pos = s.size();
            if (pos > start)
                tokens.push_back(s.substr(start, pos - start));
            start = pos + 1;
        }
        return tokens;
    };

    auto patSegs = split(pattern, '/');
    auto uriSegs = split(actualUri, '/');

    for (size_t i = 0; i < patSegs.size() && i < uriSegs.size(); ++i)
    {
        if (patSegs[i].size() >= 2 &&
            patSegs[i].front() == '{' &&
            patSegs[i].back() == '}')
            args.push_back(uriSegs[i]);
    }

    return args;
}

// ===========================================================================
// Base64 decode (pentru Basic Auth)
// ===========================================================================

std::string ESPWebServer::_base64Decode(const std::string &in)
{
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[(uint8_t)chars[i]] = i;

    int val = 0, valb = -8;
    for (uint8_t c : in)
    {
        if (T[c] == -1)
            break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0)
        {
            out += (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

// ===========================================================================
// Utilitare
// ===========================================================================

void ESPWebServer::_urlDecode(std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '+')
        {
            out += ' ';
        }
        else if (s[i] == '%' && i + 2 < s.size())
        {
            char hex[3] = {s[i + 1], s[i + 2], '\0'};
            out += static_cast<char>(strtol(hex, nullptr, 16));
            i += 2;
        }
        else
        {
            out += s[i];
        }
    }
    s = std::move(out);
}

const char *ESPWebServer::_codeToStatus(int code)
{
    switch (code)
    {
    case 200:
        return "200 OK";
    case 201:
        return "201 Created";
    case 204:
        return "204 No Content";
    case 301:
        return "301 Moved Permanently";
    case 302:
        return "302 Found";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 408:
        return "408 Request Timeout";
    case 500:
        return "500 Internal Server Error";
    default:
        return "200 OK";
    }
}

// ===========================================================================
// OTA
// ===========================================================================

void ESPWebServer::enableOTA(const std::string &path)
{
    if (_server != nullptr)
        ESP_LOGW(TAG_WEB, "enableOTA() called after start() — OTA routes NOT registered. Call before start().");
    _otaEnabled = true;
    _otaPath = path;
}

void ESPWebServer::setOtaProgressCallback(OtaProgressCallback cb)
{
    _otaProgressCb = std::move(cb);
}

void ESPWebServer::setOtaResultCallback(OtaResultCallback cb)
{
    _otaResultCb = std::move(cb);
}

bool ESPWebServer::otaInProgress() const
{
    return _otaInProgress;
}

esp_err_t ESPWebServer::_dispatchOta(httpd_req_t *req)
{
    if (!_instance)
        return ESP_FAIL;

    ESP_LOG_LEVEL_LOCAL(1, TAG_WEB, "dispatch uri=%s authRequired=%d authMode=%d",
                        _instance->_current.uri.c_str(),
                        (int)_instance->_authRequired,
                        (int)_instance->_authMode);

    // verifica autentificare daca e activa
    if (_instance->_authRequired)
    {
        bool ok = _instance->_checkAuth(req);
        if (!ok)
        {
            _instance->_sendUnauthorized(req);
            return ESP_OK;
        }
    }

    _instance->_current.req = req;
    _instance->_handleOtaUpload();
    return ESP_OK;
}

void ESPWebServer::_handleOtaUpload()
{
    httpd_req_t *req = _current.req;

    size_t totalSize = req->content_len;
    if (totalSize == 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
        return;
    }

    ESP_LOGI(TAG_WEB, "OTA start, size=%zu", totalSize);
    _otaInProgress = true;

    // verifica partitia OTA disponibila
    const esp_partition_t *updatePartition = esp_ota_get_next_update_partition(nullptr);
    if (updatePartition == nullptr)
    {
        ESP_LOGE(TAG_WEB, "OTA: no update partition found");
        _sendOtaResult(false, "No OTA partition available");
        _otaInProgress = false;
        return;
    }

    ESP_LOGI(TAG_WEB, "OTA: writing to partition '%s' at 0x%08lx, size 0x%08lx",
             updatePartition->label,
             updatePartition->address,
             updatePartition->size);

    esp_ota_handle_t otaHandle = 0;
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG_WEB, "esp_ota_begin failed: %s", esp_err_to_name(err));
        _sendOtaResult(false, std::string("OTA begin failed: ") + esp_err_to_name(err));
        _otaInProgress = false;
        return;
    }

    // riceve firmware in bucati de 1KB
    static const size_t BUF_SIZE = 1024;
    char *buf = new char[BUF_SIZE];
    size_t written = 0;
    bool hasError = false;

    while (written < totalSize)
    {
        size_t toRead = std::min(BUF_SIZE, totalSize - written);
        int received = httpd_req_recv(req, buf, toRead);

        if (received < 0)
        {
            if (received == HTTPD_SOCK_ERR_TIMEOUT)
            {
                ESP_LOGW(TAG_WEB, "OTA recv timeout at %zu/%zu", written, totalSize);
                continue; // reincearca
            }
            ESP_LOGE(TAG_WEB, "OTA recv error at %zu/%zu", written, totalSize);
            hasError = true;
            break;
        }

        if (received == 0)
        {
            ESP_LOGW(TAG_WEB, "OTA: connection closed early at %zu/%zu", written, totalSize);
            hasError = true;
            break;
        }

        // valideaza header-ul imaginii la primul chunk
        if (written == 0 && (size_t)received >= sizeof(esp_image_header_t))
        {
            auto *imgHdr = reinterpret_cast<esp_image_header_t *>(buf);
            if (imgHdr->magic != ESP_IMAGE_HEADER_MAGIC)
            {
                ESP_LOGE(TAG_WEB, "OTA: invalid image magic 0x%02x", imgHdr->magic);
                hasError = true;
                break;
            }
        }

        err = esp_ota_write(otaHandle, buf, (size_t)received);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG_WEB, "esp_ota_write failed: %s", esp_err_to_name(err));
            hasError = true;
            break;
        }

        written += (size_t)received;

        if (_otaProgressCb)
            _otaProgressCb(written, totalSize);

        ESP_LOGD(TAG_WEB, "OTA progress: %zu/%zu (%.1f%%)",
                 written, totalSize, 100.0f * written / totalSize);
    }

    delete[] buf;

    if (hasError)
    {
        esp_ota_abort(otaHandle);
        _sendOtaResult(false, "Upload failed at " + std::to_string(written) + "/" + std::to_string(totalSize));
        _otaInProgress = false;
        return;
    }

    err = esp_ota_end(otaHandle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG_WEB, "esp_ota_end failed: %s", esp_err_to_name(err));
        _sendOtaResult(false, std::string("OTA end failed: ") + esp_err_to_name(err));
        _otaInProgress = false;
        return;
    }

    err = esp_ota_set_boot_partition(updatePartition);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG_WEB, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        _sendOtaResult(false, std::string("Set boot partition failed: ") + esp_err_to_name(err));
        _otaInProgress = false;
        return;
    }

    ESP_LOGI(TAG_WEB, "OTA success! %zu bytes written. Rebooting...", written);
    _sendOtaResult(true, "Update complete. Rebooting...");
    _otaInProgress = false;

    // delay scurt ca raspunsul HTTP sa ajunga la browser inainte de restart
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

void ESPWebServer::_sendOtaResult(bool success, const std::string &message)
{
    if (!_current.req)
        return;

    if (_otaResultCb)
        _otaResultCb(success, message);

    std::string json = std::string("{\"success\":") +
                       (success ? "true" : "false") +
                       ",\"message\":\"" + message + "\"}";

    httpd_resp_set_status(_current.req, success ? "200 OK" : "500 Internal Server Error");
    httpd_resp_set_type(_current.req, "application/json");
    httpd_resp_send(_current.req, json.c_str(), (ssize_t)json.length());
}

// ===========================================================================
// Pagina HTML OTA
// ===========================================================================

// Pagina e impartita in doua bucati — intre ele se injecteaza URL-ul OTA la runtime
static const char OTA_PAGE_PART1[] =
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>Firmware Update</title><style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    "background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;"
    "align-items:center;justify-content:center;padding:1rem;}"
    ".card{background:#1a1d27;border:1px solid #2d3148;border-radius:12px;"
    "padding:2rem;width:100%;max-width:480px;box-shadow:0 8px 32px #0006;}"
    "h1{font-size:1.4rem;font-weight:600;margin-bottom:.4rem;color:#fff;}"
    ".sub{font-size:.85rem;color:#64748b;margin-bottom:1.8rem;}"
    ".drop{border:2px dashed #2d3148;border-radius:8px;padding:2.5rem 1rem;"
    "text-align:center;cursor:pointer;transition:border-color .2s,background .2s;"
    "margin-bottom:1.2rem;position:relative;}"
    ".drop:hover,.drop.over{border-color:#6366f1;background:#1e2035;}"
    ".drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;}"
    ".drop-icon{font-size:2rem;margin-bottom:.5rem;opacity:.5;}"
    ".drop-text{font-size:.9rem;color:#64748b;}"
    ".drop-text b{color:#a5b4fc;}"
    "#file-name{font-size:.8rem;color:#6366f1;margin-top:.4rem;min-height:1.2em;}"
    ".btn{width:100%;padding:.75rem;background:#6366f1;color:#fff;border:none;"
    "border-radius:8px;font-size:1rem;font-weight:500;cursor:pointer;"
    "transition:background .2s;margin-bottom:1.2rem;}"
    ".btn:hover:not(:disabled){background:#4f46e5;}"
    ".btn:disabled{opacity:.4;cursor:not-allowed;}"
    ".progress-wrap{display:none;margin-bottom:1.2rem;}"
    ".progress-bar{height:6px;background:#2d3148;border-radius:3px;overflow:hidden;}"
    ".progress-fill{height:100%;background:linear-gradient(90deg,#6366f1,#818cf8);"
    "width:0%;transition:width .3s;border-radius:3px;}"
    ".progress-label{font-size:.8rem;color:#64748b;margin-top:.4rem;text-align:right;}"
    ".status{display:none;padding:.75rem 1rem;border-radius:8px;font-size:.9rem;"
    "font-weight:500;text-align:center;}"
    ".status.ok{background:#052e16;color:#4ade80;border:1px solid #166534;}"
    ".status.err{background:#2d0a0a;color:#f87171;border:1px solid #7f1d1d;}"
    ".meta{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1.5rem;}"
    ".badge{font-size:.75rem;padding:.2rem .6rem;border-radius:20px;"
    "background:#1e2035;border:1px solid #2d3148;color:#94a3b8;}"
    "</style></head><body><div class=\"card\">"
    "<h1>Firmware Update</h1>"
    "<p class=\"sub\">Upload a compiled .bin firmware file</p>"
    "<div class=\"meta\" id=\"meta\"></div>"
    "<div class=\"drop\" id=\"drop\">"
    "<input type=\"file\" id=\"file\" accept=\".bin\">"
    "<div class=\"drop-icon\">&#128190;</div>"
    "<div class=\"drop-text\">Drop .bin here or <b>browse</b></div>"
    "<div id=\"file-name\"></div>"
    "</div>"
    "<button class=\"btn\" id=\"btn\" disabled>Select a file first</button>"
    "<div class=\"progress-wrap\" id=\"pw\">"
    "<div class=\"progress-bar\"><div class=\"progress-fill\" id=\"pf\"></div></div>"
    "<div class=\"progress-label\" id=\"pl\">0%</div>"
    "</div>"
    "<div class=\"status\" id=\"st\"></div>"
    "<script>const OTA_URL='";

// URL-ul OTA e injectat aici la runtime, apoi continua cu:
static const char OTA_PAGE_PART2[] =
    "';"
    "const file=document.getElementById('file');"
    "const btn=document.getElementById('btn');"
    "const pw=document.getElementById('pw');"
    "const pf=document.getElementById('pf');"
    "const pl=document.getElementById('pl');"
    "const st=document.getElementById('st');"
    "const fn=document.getElementById('file-name');"
    "const drop=document.getElementById('drop');"
    "fetch('/ota/info').then(r=>r.json()).then(d=>{"
    "  const m=document.getElementById('meta');"
    "  m.innerHTML='<span class=\"badge\">v'+d.version+'</span>'"
    "    +'<span class=\"badge\">'+(d.date||'unknown')+'</span>'"
    "    +'<span class=\"badge\">'+(d.idf||'')+'</span>';"
    "}).catch(()=>{});"
    "drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('over');});"
    "drop.addEventListener('dragleave',()=>drop.classList.remove('over'));"
    "drop.addEventListener('drop',e=>{"
    "  e.preventDefault();drop.classList.remove('over');"
    "  if(e.dataTransfer.files[0])setFile(e.dataTransfer.files[0]);"
    "});"
    "file.addEventListener('change',()=>{if(file.files[0])setFile(file.files[0]);});"
    "function setFile(f){"
    "  fn.textContent=f.name+' ('+Math.round(f.size/1024)+'\u00a0KB)';"
    "  btn.disabled=false;btn.textContent='Flash Firmware';btn._file=f;"
    "}"
    "btn.addEventListener('click',async()=>{"
    "  const f=btn._file;if(!f)return;"
    "  btn.disabled=true;btn.textContent='Uploading...';"
    "  pw.style.display='block';st.style.display='none';"
    "  const xhr=new XMLHttpRequest();"
    "  xhr.open('POST',OTA_URL);"
    "  xhr.upload.onprogress=e=>{"
    "    const p=e.lengthComputable?Math.round(100*e.loaded/e.total):0;"
    "    pf.style.width=p+'%';pl.textContent=p+'%';"
    "  };"
    "  xhr.onload=()=>{"
    "    const ok=xhr.status===200;"
    "    st.className='status '+(ok?'ok':'err');"
    "    try{const d=JSON.parse(xhr.responseText);st.textContent=d.message;}"
    "    catch(e){st.textContent=ok?'Update complete!':'Update failed';}"
    "    st.style.display='block';"
    "    btn.textContent=ok?'Done \u2014 rebooting...':'Try again';"
    "    if(!ok){btn.disabled=false;}"
    "  };"
    "  xhr.onerror=()=>{"
    "    st.className='status err';st.textContent='Connection error';"
    "    st.style.display='block';btn.disabled=false;btn.textContent='Try again';"
    "  };"
    "  xhr.send(f);"
    "});"
    "</script></div></body></html>";

void ESPWebServer::_handleOtaPage()
{
    httpd_req_t *req = _current.req;

    // trimite pagina in doua bucati cu URL-ul OTA injectat la mijloc
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send_chunk(req, OTA_PAGE_PART1, (ssize_t)sizeof(OTA_PAGE_PART1) - 1);
    httpd_resp_send_chunk(req, _otaPath.c_str(), (ssize_t)_otaPath.size());
    httpd_resp_send_chunk(req, OTA_PAGE_PART2, (ssize_t)sizeof(OTA_PAGE_PART2) - 1);
    httpd_resp_send_chunk(req, nullptr, 0);
}

void ESPWebServer::_handleOtaInfo()
{
    const esp_app_desc_t *desc = esp_ota_get_app_description();

    std::string json = "{\"version\":\"";
    json += desc->version;
    json += "\",\"date\":\"";
    json += desc->date;
    json += " ";
    json += desc->time;
    json += "\",\"idf\":\"";
    json += desc->idf_ver;
    json += "\",\"project\":\"";
    json += desc->project_name;
    json += "\"}";

    httpd_resp_set_status(_current.req, "200 OK");
    httpd_resp_set_type(_current.req, "application/json");
    httpd_resp_send(_current.req, json.c_str(), (ssize_t)json.size());
}

esp_err_t ESPWebServer::_dispatchOtaPage(httpd_req_t *req)
{
    if (!_instance)
        return ESP_FAIL;

    ets_printf(TAG_WEB, "dispatch uri=%s authRequired=%d authMode=%d",
               _instance->_current.uri.c_str(),
               (int)_instance->_authRequired,
               (int)_instance->_authMode);

    if (_instance->_authRequired)
    {
        bool ok = _instance->_checkAuth(req);
        if (!ok)
        {
            _instance->_sendUnauthorized(req);
            return ESP_OK;
        }
    }
    _instance->_current.req = req;
    _instance->_handleOtaPage();
    return ESP_OK;
}

esp_err_t ESPWebServer::_dispatchOtaInfo(httpd_req_t *req)
{
    if (!_instance)
        return ESP_FAIL;

    ets_printf(TAG_WEB, "dispatch uri=%s authRequired=%d authMode=%d",
               _instance->_current.uri.c_str(),
               (int)_instance->_authRequired,
               (int)_instance->_authMode);

    if (_instance->_authRequired)
    {
        bool ok = _instance->_checkAuth(req);
        if (!ok)
        {
            _instance->_sendUnauthorized(req);
            return ESP_OK;
        }
    }
    _instance->_current.req = req;
    _instance->_handleOtaInfo();
    return ESP_OK;
}

void ESPWebServer::beginBinary(int code, const char *contentType,
                               size_t contentLength, const char *filename)
{
    if (!_current.req)
        return;
    httpd_resp_set_status(_current.req, _codeToStatus(code));
    httpd_resp_set_type(_current.req, contentType);

    // Content-Length explicit — browserul stie cat sa astepte si afiseaza progress
    char lenStr[24];
    snprintf(lenStr, sizeof(lenStr), "%zu", contentLength);
    httpd_resp_set_hdr(_current.req, "Content-Length", lenStr);

    // Content-Disposition: attachment — browser descarca, nu afiseaza
    if (filename)
    {
        // buf pe heap ca httpd_resp_set_hdr nu copiaza stringul
        // trebuie sa ramana valid pana la sfarsitul request-ului
        // folosim un member static — suficient pentru un singur request la un moment dat
        static char dispBuf[128];
        snprintf(dispBuf, sizeof(dispBuf), "attachment; filename=\"%s\"", filename);
        httpd_resp_set_hdr(_current.req, "Content-Disposition", dispBuf);
    }

    _current.chunkedActive = true;
}

void ESPWebServer::sendBinaryChunk(const void *buf, size_t len)
{
    if (!_current.req || len == 0)
        return;
    httpd_resp_send_chunk(_current.req, static_cast<const char *>(buf), (ssize_t)len);
}

void ESPWebServer::endBinary()
{
    if (!_current.req)
        return;
    httpd_resp_send_chunk(_current.req, nullptr, 0);
    _current.chunkedActive = false;
}

void ESPWebServer::_killHttpdZombieTasks()
{
    ESP_LOGI(TAG_WEB, "Try _killHttpdZombieTasks");

    for(int i = 0 ; i < 5 ; i ++)
    {
        TaskHandle_t h = xTaskGetHandle("httpd");
        if (h != nullptr) 
        {
            vTaskDelete(h);
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        else
        {
            return;
        }
    }
}