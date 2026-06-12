# webview_bridge.py - webview bridge module
# Purpose: Provide the application bridge between Python actions and the pywebview window.

import json
import os
import threading

import webview


class WebviewBridge:
    def __init__(self, window_title="SystemShield"):
        self._window_title = window_title
        self._ui_root = ""
        self._api = None
        self._window = None
        self._loaded = False
        self._exposed = {}
        self._pending_js = []
        self._pending_lock = threading.Lock()

    def init(self, ui_root):
        self._ui_root = os.path.abspath(ui_root)

    def expose(self, func):
        self._exposed[func.__name__] = func
        return func

    def set_api(self, api):
        self._api = api

    def build_api(self):
        class BridgeApi:
            pass

        for function_name, function in self._exposed.items():
            def _method(_self, *args, __function=function, **kwargs):
                return __function(*args, **kwargs)

            _method.__name__ = function_name
            setattr(BridgeApi, function_name, _method)

        return BridgeApi()

    def update_scan_progress(self, message, progress):
        self.dispatch_js("update_scan_progress", message, progress)

    def dispatch_js(self, function_name, *args):
        payload = list(args)
        if not self._window or not self._loaded:
            with self._pending_lock:
                self._pending_js.append((function_name, payload))
            return None

        script = "window.__appBridgeDispatch({0}, {1});".format(
            json.dumps(function_name),
            json.dumps(payload),
        )
        try:
            return self._window.evaluate_js(script)
        except Exception:
            return None

    def _flush_pending_js(self):
        with self._pending_lock:
            pending = list(self._pending_js)
            self._pending_js.clear()
        for function_name, args in pending:
            self.dispatch_js(function_name, *args)

    def _on_loaded(self):
        self._loaded = True
        self._flush_pending_js()

    def start(self, start_page, size=None, position=None):
        if not self._ui_root:
            raise RuntimeError("UI root was not initialized before start().")
        if self._api is None:
            raise RuntimeError("Python API bridge was not set before start().")

        width, height = size or (1280, 820)
        x = None
        y = None
        if position:
            x, y = position

        index_path = os.path.abspath(os.path.join(self._ui_root, start_page))
        icon_path = os.path.join(self._ui_root, "data", "icon.ico")
        storage_root = os.path.join(
            os.getenv("LOCALAPPDATA") or os.path.expanduser("~"),
            "SystemShield",
            "pywebview",
        )
        os.makedirs(storage_root, exist_ok=True)

        webview.settings["ALLOW_DOWNLOADS"] = True
        self._window = webview.create_window(
            self._window_title,
            url=index_path,
            js_api=self._api,
            width=width,
            height=height,
            x=x,
            y=y,
            min_size=(1100, 720),
            text_select=False,
            zoomable=False,
            draggable=False,
            resizable=True,
            confirm_close=False,
            background_color="#f4f7fb",
        )
        self._window.events.loaded += self._on_loaded

        webview.start(
            gui="edgechromium",
            debug=False,
            http_server=True,
            private_mode=False,
            storage_path=storage_root,
            icon=icon_path if os.path.isfile(icon_path) else None,
        )
