/* bridge.js - frontend bridge module
   Purpose: Provide the application bridge between the UI and the pywebview API. */

(function (global) {
    var exposed = Object.create(null);

    var bridgeReady = new Promise(function (resolve) {
        if (global.pywebview && global.pywebview.api) {
            resolve(global.pywebview.api);
            return;
        }
        global.addEventListener('pywebviewready', function () {
            resolve(global.pywebview.api);
        }, { once: true });
    });

    function invokePython(name, args) {
        return bridgeReady.then(function (api) {
            if (!api || typeof api[name] !== 'function') {
                throw new Error('Python bridge method not available: ' + name);
            }
            return api[name].apply(api, args || []);
        });
    }

    var bridge = {
        expose: function (fn) {
            if (typeof fn === 'function' && fn.name) {
                exposed[fn.name] = fn;
            }
            return fn;
        }
    };

    global.__appBridgeDispatch = function (name, args) {
        var fn = exposed[name];
        if (typeof fn !== 'function') {
            return null;
        }
        try {
            return fn.apply(global, Array.isArray(args) ? args : []);
        } catch (error) {
            console.error(error);
            return null;
        }
    };

    global.appBridge = new Proxy(bridge, {
        get: function (target, prop) {
            if (prop in target) {
                return target[prop];
            }
            return function () {
                var args = Array.prototype.slice.call(arguments);
                return function () {
                    return invokePython(String(prop), args);
                };
            };
        }
    });
})(window);
