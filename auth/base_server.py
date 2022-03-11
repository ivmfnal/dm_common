# common functionality for Auth, GUI and Data servers

from webpie import WPApp, Response, WPHandler
from wsdbtools import ConnectionPool
from metacat.util import to_str, to_bytes, \
    SignedToken, SignedTokenExpiredError, SignedTokenImmatureError, SignedTokenUnacceptedAlgorithmError, SignedTokenSignatureVerificationError
import psycopg2, json, time, secrets, traceback, hashlib, pprint, os, yaml
from metacat.db import DBUser
from urllib.parse import quote_plus, unquote_plus

class BaseApp(WPApp):

    def __init__(self, cfg, root_handler, **args):
        WPApp.__init__(self, root_handler, **args)
        self.Cfg = cfg
        
        db_config = cfg["database"]
        connstr = "host=%(host)s port=%(port)s dbname=%(dbname)s user=%(user)s password=%(password)s" % db_config
        self.DB = ConnectionPool(postgres=connstr, max_idle_connections=3)
        self.DBSchema = db_config.get("schema")

        if "user_database" in cfg:
            connstr = "host=%(host)s port=%(port)s dbname=%(dbname)s user=%(user)s password=%(password)s" % cfg["user_database"]
            self.UserDB = ConnectionPool(postgres=connstr, max_idle_connections=3)
            self.UserDBSchema = cfg["user_database"].get("schema")
        else:
            self.UserDB = self.DB
            self.UserDBSchema = self.DBSchema

        self.AuthConfig = cfg.get("authentication")
        secret = self.AuthConfig.get("secret") 
        if secret is None:    
            raise ValueError("Authentication secret not found in the configuration")
            self.TokenSecret = secrets.token_bytes(128)     # used to sign tokens
        else:         
            h = hashlib.sha256()
            h.update(to_bytes(secret))      
            self.TokenSecret = h.digest()

    def auth_config(self, method):
        return self.AuthConfig.get(method)
                
    def connect(self):
        conn = self.DB.connect()
        #print("conn: %x" % (id(conn),), "   idle connections:", ",".join("%x" % (id(c),) for c in self.DB.IdleConnections))
        if self.DBSchema:
            conn.cursor().execute(f"set search_path to {self.DBSchema}")
        return conn
        
    db = connect        # for compatibility
    
    def user_db(self):
        conn = self.UserDB.connect()
        if self.UserDBSchema:
            conn.cursor().execute(f"set search_path to {self.UserDBSchema}")
        return conn
        
    def get_digest_password(self, realm, username):
        db = self.connect()
        u = DBUser.get(db, username)
        if u is None:
            return None
        hashed = u.authenticator("password").password_for_digest()
        return hashed

    TokenExpiration = 24*3600*7

    def user_from_request(self, request):
        encoded = request.cookies.get("auth_token") or request.headers.get("X-Authentication-Token")
        #print("server.user_from_request: encoded:", encoded)
        if not encoded: 
            return None, "Token not found"
        try:    
            token = SignedToken.from_bytes(encoded)
            #print("server.user_from_request: token:", token)
            #print("                          secret:", self.TokenSecret)
            token.verify(self.TokenSecret)
        except SignedTokenExpiredError:
            return None, "Token expired"           
        except SignedTokenImmatureError:
            return None, "Token immature"           
        except SignedTokenUnacceptedAlgorithmError:
            return None, "Invalid token algorithm"           
        except SignedTokenSignatureVerificationError:
            return None, "Invalid token"           
        except Exception as e:
            return None, str(e)
        else:
            return token.get("sub"), None

    def encoded_token_from_request(self, request):
        encoded = request.cookies.get("auth_token") or request.headers.get("X-Authentication-Token")
        if not encoded: return None
        try:    token = SignedToken.decode(encoded, self.TokenSecret, verify_times=True)
        except: return None             # invalid token
        return encoded

    def generate_token(self, user, payload={}, expiration=None):
        expiration = expiration or self.TokenExpiration
        token = SignedToken(payload, subject=user, expiration=expiration)
        return token, token.encode(self.TokenSecret)

    def response_with_auth_cookie(self, user, redirect):
        #print("response_with_auth_cookie: user:", user, "  redirect:", redirect)
        _, encoded = self.generate_token(user, {"user": user})
        #print("Server.App.response_with_auth_cookie: new token created:", token.TID)
        if redirect:
            resp = Response(status=302, headers={"Location": redirect})
        else:
            resp = Response(status=200, content_type="text/plain")
        #print ("response:", resp, "  reditrect=", redirect)
        resp.headers["X-Authentication-Token"] = to_str(encoded)
        resp.set_cookie("auth_token", encoded, max_age = int(self.TokenExpiration))
        return resp

    def response_with_unset_auth_cookie(self, redirect):
        if redirect:
            resp = Response(status=302, headers={"Location": redirect})
        else:
            resp = Response(status=200, content_type="text/plain")
        try:    resp.set_cookie("auth_token", "-", max_age=100)
        except: pass
        return resp

    def verify_token(self, encoded):
        try:
            token = SignedToken.decode(encoded, self.TokenSecret, verify_times=True)
        except Exception as e:
            return False, e
        return True, None
        
class BaseHandler(WPHandler):
    
    def connect(self):
        return self.App.connect()

    def text_chunks(self, gen, chunk=100000):
        buf = []
        size = 0
        for x in gen:
            n = len(x)
            buf.append(x)
            size += n
            if size >= chunk:
                yield "".join(buf)
                size = 0
                buf = []
        if buf:
            yield "".join(buf)
            
    def authenticated_user(self):
        username, error = self.App.user_from_request(self.Request)
        if not username:    
            #print("authenticated_user(): error:", error)
            return None
        db = self.App.db()
        return DBUser.get(db, username)

    def messages(self, args):
        return {k: unquote_plus(args.get(k,"")) for k in ("error", "message")}
        
    def jinja_globals(self):
        return {"GLOBAL_User":self.authenticated_user()}

class AuthHandler(BaseHandler):

    def whoami(self, request, relpath, **args):
        user, error = self.App.user_from_request(request)
        return user or "", "text/plain"
        
    def token(self, request, relpath, **args):
        return self.App.encoded_token_from_request(request)+"\n"
        
    def _auth_digest(self, request_env, redirect):
        from metacat.util import digest_server
        # give them cookie with the signed token
        
        ok, data = digest_server("metadata", request_env, self.App.get_digest_password)
        if ok:
            #print("AuthHandler.auth: digest_server ok")
            resp = self.App.response_with_auth_cookie(data, redirect)
            return resp
        elif data:
            return Response("Authorization required", status=401, headers={
                'WWW-Authenticate': data
            })

        else:
            return "Authentication failed\n", 403

    def _auth_ldap(self, request, redirect, username):
        
        # check HTTPS here
        
        if username:
            password = to_str(request.body.strip())
        else:
            username, password = request.body.split(b":",1)
            username = to_str(username)
            password = to_str(password)
        db = self.App.user_db()
        u = DBUser.get(db, username)
        config = self.App.auth_config("ldap")
        #print("ldap config:", config)
        if u.authenticate("ldap", config, password):
            return self.App.response_with_auth_cookie(username, redirect)
        else:
            return "Authentication failed\n", 403
            
    def _auth_x509(self, request, redirect, username):
        ssl = request.environ.get("HTTPS") == "on" or request.environ.get("REQUEST_SCHEME") == "https"
        if not ssl:
            return "Authentication failed\n", 403
            
        db = self.App.user_db()
        u = DBUser.get(db, username)
        if u.authenticate("x509", None, {
            "subject_dn":   request.environ.get("SSL_CLIENT_S_DN"),
            "issuer_dn":    request.environ.get("SSL_CLIENT_I_DN")
        }):
            return self.App.response_with_auth_cookie(username, redirect)
        else:
            return "Authentication failed\n", 403
        
    def auth(self, request, relpath, redirect=None, method="password", username=None, **args):
        if method == "x509":
            return self._auth_x509(request, redirect, username)
        elif method == "digest":
            return self._auth_digest(request.environ, redirect)
        elif method == "ldap":
            return self._auth_ldap(request, redirect, username)
        else:
            return "Unknown authentication method\n", 400
            
    def mydn(self, request, relpath):
        ssl = request.environ.get("HTTPS") == "on" or request.environ.get("REQUEST_SCHEME") == "https"
        if not ssl:
            return "Use HTTPS connection\n", 400
        return json.dumps({
            "subject":  request.environ.get("SSL_CLIENT_S_DN",""),
            "issuer":  request.environ.get("SSL_CLIENT_I_DN","")
        }), "text/json"
        
    def logout(self, request, relpath, redirect=None, **args):
        return self.App.response_with_unset_auth_cookie(redirect)

    def login(self, request, relpath, redirect=None, **args):
        return self.render_to_response("login.html", redirect=redirect, **self.messages(args))
        
    def do_login(self, request, relpath, **args):
        username = request.POST["username"]
        password = request.POST["password"]
        redirect = request.POST.get("redirect", self.scriptUri() + "/gui/index")
        #print("redirect:", redirect)
        db = self.App.user_db()
        u = DBUser.get(db, username)
        if not u:
            #print("authentication error")
            self.redirect("./login?message=User+%s+not+found" % (username,))
        
        ok = u.authenticate("password", None, password)
        if not ok:
            ok = u.authenticate("ldap", self.App.auth_config("ldap"), password)

        if not ok:
            self.redirect("./login?error=%s" % (quote_plus("Authentication error"),))
            
        #print("authenticated")
        return self.App.response_with_auth_cookie(username, redirect)

    def verify(self, request, relpath, **args):
        username, error = self.App.user_from_request(request)
        return ("OK","text/plain") if username else (error, 403)

