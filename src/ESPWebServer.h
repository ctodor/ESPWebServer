#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "esp_http_server.h"
#include "esp_ota_ops.h"

// ---------------------------------------------------------------------------
// Tipuri handlere
// ---------------------------------------------------------------------------
using WebHandler0 = std::function<void()>;
using WebHandler  = std::function<void()>;

// ---------------------------------------------------------------------------
// AuthMode — metoda de autentificare
// ---------------------------------------------------------------------------
enum class AuthMode {
    None,       // ruta publica
    Basic,      // HTTP Basic Auth (username:password in header Authorization)
    Session,    // cookie de sesiune generat la login
};

// ---------------------------------------------------------------------------
// RouteEntry
// ---------------------------------------------------------------------------
struct RouteEntry {
    std::string uriPattern;
    std::string uriEsp;
    http_method method;
    WebHandler0 handler;
    bool        hasPathArg;
    bool        requireAuth;  // true = ruta protejata
};

// ---------------------------------------------------------------------------
// ESPWebServer
//
// Autentificare:
//   setCredentials("user", "pass")      — seteaza username/password
//   setAuthMode(AuthMode::Basic)        — HTTP Basic (browser afiseaza popup)
//   setAuthMode(AuthMode::Session)      — cookie de sesiune, necesita /login
//   setAuthExclude({"/login", "/css"})  — rute publice chiar cu auth global
//   requireAuth(true)                   — protejeaza toate rutele implicit
//
// Modul Session adauga automat rutele:
//   POST /login  — body: username=x&password=y  → seteaza cookie sesiune
//   POST /logout — sterge cookie sesiunea
// ---------------------------------------------------------------------------
class ESPWebServer {
public:
    explicit ESPWebServer(uint16_t port           = 80,
                          uint8_t  maxSockets     = 7,
                          uint8_t  recvTimeoutSec = 5,
                          uint8_t  sendTimeoutSec = 5);
    ~ESPWebServer();

    // ----- inregistrare rute -----
    void on(const std::string &path, WebHandler0 handler);
    void on(const std::string &path, http_method method, WebHandler0 handler);
    void onNotFound(WebHandler0 handler);

    // ----- autentificare -----

    // seteaza credentialele (un singur user — suficient pentru IoT)
    void setCredentials(const std::string &username, const std::string &password);

    // alege metoda de autentificare
    void setAuthMode(AuthMode mode);

    // protejeaza toate rutele implicit (exceptiile se adauga cu setAuthExclude)
    void setAuthRequired(bool required);

    // rute excluse de la autentificare (ex: pagina de login, fisiere statice)
    void setAuthExclude(const std::vector<std::string> &paths);

    // durata sesiunii in secunde (implicit 3600 = 1h), doar pentru AuthMode::Session
    void setSessionTimeout(uint32_t seconds);

    // ----- OTA -----
    // activeaza ruta POST /ota/update pentru upload firmware .bin
    // OTA e protejata de auth daca setAuthRequired(true) e activ
    // callback apelat la sfarsit: true=succes, false=eroare
    using OtaProgressCallback = std::function<void(size_t written, size_t total)>;
    using OtaResultCallback   = std::function<void(bool success, const std::string &message)>;

    void enableOTA(const std::string &path = "/ota/update");
    void setOtaProgressCallback(OtaProgressCallback cb);
    void setOtaResultCallback(OtaResultCallback cb);
    bool otaInProgress() const;

    // ----- ciclu de viata -----
    bool start();
    void stop();
    bool restart();
    bool isRunning() const;

    // ----- API request (apelat din handlere) -----
    void        send(int code, const char *contentType, const std::string &body = "");
    void        send(int code, const char *contentType, const char *body, size_t len);

    // transfer chunked — pentru pagini mari
    // inlocuieste setContentLength(CONTENT_LENGTH_UNKNOWN) + sendContent() din Arduino WebServer
    void        beginChunked(int code, const char *contentType);
    void        sendContent(const std::string &chunk);
    void        sendContent(const char *chunk, size_t len);
    void        endChunked();
    std::string arg(const std::string &name) const;
    bool        hasArg(const std::string &name) const;
    size_t      args() const;                          // numarul total de parametri
    std::string arg(size_t index) const;               // valoarea parametrului la index
    std::string argName(size_t index) const;           // numele parametrului la index
    std::string uri() const;
    std::string pathArg(uint8_t index) const;
    http_method method() const;
    std::string header(const std::string &name) const;
    void        sendHeader(const std::string &name, const std::string &value);
    const std::string &body() const;

    void beginBinary(int code, const char *contentType,size_t contentLength, const char *filename = nullptr);
    void sendBinaryChunk(const void *buf, size_t len);
    void endBinary();

    // true daca request-ul curent este autentificat
    bool isAuthenticated() const;

private:
    // ----- config -----
    uint16_t _port;
    uint8_t  _maxSockets;
    uint8_t  _recvTimeout;
    uint8_t  _sendTimeout;

    // ----- auth config -----
    AuthMode    _authMode        = AuthMode::None;
    bool        _authRequired    = false;
    uint32_t    _sessionTimeout  = 3600;
    std::string _username;
    std::string _password;
    std::string _passwordHash;   // SHA-256 hex al parolei

    // ----- OTA state -----
    bool                _otaEnabled   = false;
    bool                _otaInProgress = false;
    std::string         _otaPath;
    std::string         _otaPagePath;
    std::string         _otaInfoPath;
    OtaProgressCallback _otaProgressCb;
    OtaResultCallback   _otaResultCb;

    void _handleOtaUpload();
    void _handleOtaPage();
    void _handleOtaInfo();
    void _sendOtaResult(bool success, const std::string &message);
    static esp_err_t _dispatchOta(httpd_req_t *req);
    static esp_err_t _dispatchOtaPage(httpd_req_t *req);
    static esp_err_t _dispatchOtaInfo(httpd_req_t *req);
    std::set<std::string> _authExclude;

    // ----- sesiuni active: token -> expiry (unix seconds) -----
    std::map<std::string, uint32_t> _sessions;

    // ----- server & rute -----
    httpd_handle_t          _server = nullptr;
    std::vector<RouteEntry> _routes;
    std::vector<RouteEntry> _loginRoutes;
    WebHandler0             _notFoundHandler;

    // ----- starea request-ului curent -----
    struct CurrentRequest {
        httpd_req_t                       *req           = nullptr;
        http_method                        method        = HTTP_GET;
        std::string                        uri;
        std::string                        body;
        std::map<std::string, std::string> params;
        std::vector<std::string>           pathArgs;
        bool                               authenticated = false;
        bool                               chunkedActive = false;
    };
    CurrentRequest _current;

    static ESPWebServer *_instance;

    // ----- auth helpers -----
    bool        _checkAuth(httpd_req_t *req);
    bool        _checkBasicAuth(httpd_req_t *req);
    bool        _checkSessionAuth(httpd_req_t *req);
    void        _sendUnauthorized(httpd_req_t *req);
    bool        _isExcluded(const std::string &uri) const;
    std::string _generateToken() const;
    std::string _getCookie(httpd_req_t *req, const std::string &name) const;
    uint32_t    _now() const;

    // rute login/logout adaugate automat in modul Session
    void _handleLogin();
    void _handleLogout();

    // ----- internals -----
    void _registerRoutes();
    void _populateCurrent(httpd_req_t *req, const RouteEntry &route);
    void _killHttpdZombieTasks();

    static std::string               _translateUri(const std::string &p, bool &hasArg);
    static std::vector<std::string>  _extractPathArgs(const std::string &pattern,
                                                       const std::string &uri);
    static std::map<std::string, std::string> _parseParams(httpd_req_t *req,
                                                            const std::string &body);
    static void        _parseFormEncoded(const std::string &data,
                                         std::map<std::string, std::string> &out);
    static std::string _base64Decode(const std::string &in);
    static void        _urlDecode(std::string &s);
    static const char *_codeToStatus(int code);

    static esp_err_t _dispatch(httpd_req_t *req);
    static esp_err_t _handle404(httpd_req_t *req, httpd_err_code_t err);
};

// ---------------------------------------------------------------------------
// UriTemplate — inlocuieste UriBraces din Arduino WebServer
// ---------------------------------------------------------------------------
struct UriTemplate {
    explicit UriTemplate(const std::string &p) : path(p) {}
    std::string path;
    operator std::string() const { return path; }
};
