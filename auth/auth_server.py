from dm_common.auth import BaseApp, AuthHandler

import time, os, yaml
from urllib.parse import quote_plus, unquote_plus

class AuthApp(BaseApp):
    pass

def create_application(config_path=None):
    config_path = config_path or os.environ.get("AUTH_SERVER_CFG")
    if not config_path:
        print("Config file is not defined. Use AUTH_SERVER_CFG environment variable")
    config = yaml.load(open(config_path, "r"), Loader=yaml.SafeLoader)
    app = AuthApp(config, AuthHandler)
    templdir = config.get("templates", "")
    if templdir.startswith("$"):
        templdir = os.environ[templdir[1:]]
    app.initJinjaEnvironment(tempdirs=[templdir, "."])
    return app
    
if __name__ == "__main__":
    from webpie import HTTPServer
    import sys, getopt
    
    Usage = """
    python auth_server.py [-p <port>] [-c <config.yaml>]
    """

    opts, args = getopt.getopt(sys.argv[1:], "c:p:")
    opts = dict(opts)
    config_file = opts.get("-c", os.environ.get("AUTH_SERVER_CFG"))
    if not config_file:
        print("Configuration file must be provided either using -c command line option or via AUTH_SERVER_CFG environment variable")
        sys.exit(1)
    
    config = yaml.load(open(config_file, "r"), Loader=yaml.SafeLoader)
    auth_config = config["authentication"]
    port = int(opts.get("-p", auth_config.get("port", -1)))
    if port == -1:
        print("AuthServer port is not configured")
        sys.exit(1)

    key = cert = ca_file = None
    if "ssl" in config:
        key = config["ssl"]["key"]
        cert = config["ssl"]["cert"]
        ca_file = config["ssl"]["ca_file"]
        
    application = create_application(config_file)
    
    server = HTTPServer(port, application, cert, key, verify="optional", ca_file=ca_file, debug=sys.stdout, logging=True)
    server.run()
else:
    application = create_application()
