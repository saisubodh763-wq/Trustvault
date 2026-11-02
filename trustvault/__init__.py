"""TrustVault application factory."""
from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from . import cli, routes_admin, routes_auth, routes_docs, web
from .config import Config, from_env
from .db import connect, init_db

UI_DIR = Path(__file__).parent / "ui"


def create_app(config: Config | None = None) -> Flask:
    conf = config or from_env()
    conf.validate()
    conf.blob_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    init_db(conf.db_path)

    app = Flask(__name__, static_folder=None)        # no implicit static route
    app.config["TV"] = conf
    app.config["MAX_CONTENT_LENGTH"] = conf.max_upload_bytes + 64 * 1024
    app.config["TESTING"] = conf.testing
    if conf.proxy_hops:
        # Only trust X-Forwarded-* when told how many proxies sit in front.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=conf.proxy_hops, x_proto=conf.proxy_hops,
                                x_host=conf.proxy_hops)

    web.install(app)
    app.register_blueprint(routes_auth.bp)
    app.register_blueprint(routes_docs.bp)
    app.register_blueprint(routes_admin.bp)

    @app.get("/healthz")
    @web.public
    def healthz():
        return jsonify({"status": "ok"})

    @app.get("/")
    @web.public
    def index():
        return send_from_directory(UI_DIR, "index.html")

    @app.get("/ui/<path:filename>")
    @web.public
    def ui_asset(filename):
        return send_from_directory(UI_DIR, filename)

    cli.register(app)
    return app
