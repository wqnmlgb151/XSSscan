// DOM XSS sink hooks — injected via Page.addScriptToEvaluateOnNewDocument
// before page navigation. Intercepts dangerous DOM/JS operations and records
// only when the injected xsscan marker flows through the sink.
//
// Unlike post-hoc DOM scanning (which checks "is marker anywhere in the page?"),
// sink hooking answers "did the marker actually pass through innerHTML / eval /
// document.write / setTimeout / Function constructor?" — eliminating false
// positives from marker-in-URL, marker-in-cookie, and marker-in-static-source.

(function() {
    'use strict';
    var sinks = [];
    var MARKER = '__MARKER_PLACEHOLDER__';
    if (!MARKER || MARKER.length < 6) { return; }

    function record(sinkName, value) {
        if (sinks.length >= 100) { return; }
        if (value && typeof value === 'string' && value.length >= MARKER.length && value.indexOf(MARKER) !== -1) {
            sinks.push({sink: sinkName, value: value.substring(0, 300)});
        }
    }

    // --- Element.prototype.innerHTML ---
    try {
        var desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (desc && desc.set) {
            Object.defineProperty(Element.prototype, 'innerHTML', {
                get: desc.get,
                set: function(v) { record('innerHTML', String(v)); desc.set.call(this, v); },
                configurable: true, enumerable: true
            });
        }
    } catch(e) {}

    // --- Element.prototype.outerHTML ---
    try {
        var outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        if (outerDesc && outerDesc.set) {
            Object.defineProperty(Element.prototype, 'outerHTML', {
                get: outerDesc.get,
                set: function(v) { record('outerHTML', String(v)); outerDesc.set.call(this, v); },
                configurable: true, enumerable: true
            });
        }
    } catch(e) {}

    // --- document.write / document.writeln ---
    try {
        var origWrite = Document.prototype.write;
        Document.prototype.write = function() {
            for (var i = 0; i < arguments.length; i++) { record('document.write', String(arguments[i])); }
            return origWrite.apply(this, arguments);
        };
        var origWriteln = Document.prototype.writeln;
        Document.prototype.writeln = function() {
            for (var i = 0; i < arguments.length; i++) { record('document.writeln', String(arguments[i])); }
            return origWriteln.apply(this, arguments);
        };
    } catch(e) {}

    // --- Element.insertAdjacentHTML ---
    try {
        var origInsert = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(pos, html) {
            record('insertAdjacentHTML', html);
            return origInsert.call(this, pos, html);
        };
    } catch(e) {}

    // --- eval ---
    try {
        var origEval = window.eval;
        window.eval = function(code) { record('eval', String(code)); return origEval(code); };
    } catch(e) {}

    // --- Function constructor ---
    try {
        var origFunc = Function;
        Function = function() {
            // Allocation-free: last argument is the function body
            var body = arguments.length > 0 ? arguments[arguments.length - 1] : '';
            record('Function', String(body));
            return origFunc.apply(this, arguments);
        };
        Function.prototype = origFunc.prototype;
    } catch(e) {}

    // --- setTimeout / setInterval (string form) ---
    try {
        var origST = window.setTimeout;
        window.setTimeout = function(fn, delay) {
            if (typeof fn === 'string') { record('setTimeout', fn); }
            return origST.call(this, fn, delay);
        };
        var origSI = window.setInterval;
        window.setInterval = function(fn, delay) {
            if (typeof fn === 'string') { record('setInterval', fn); }
            return origSI.call(this, fn, delay);
        };
    } catch(e) {}

    // --- location.assign / location.replace ---
    try {
        var origAssign = Location.prototype.assign || window.Location.prototype.assign;
        if (origAssign) {
            Location.prototype.assign = function(url) { record('location.assign', String(url)); return origAssign.call(this, url); };
        }
        var origReplace = Location.prototype.replace || window.Location.prototype.replace;
        if (origReplace) {
            Location.prototype.replace = function(url) { record('location.replace', String(url)); return origReplace.call(this, url); };
        }
    } catch(e) {}

    // --- document.cookie setter ---
    try {
        var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        if (cookieDesc && cookieDesc.set) {
            Object.defineProperty(Document.prototype, 'cookie', {
                get: cookieDesc.get,
                set: function(v) { record('document.cookie', String(v)); cookieDesc.set.call(this, v); },
                configurable: true, enumerable: true
            });
        }
    } catch(e) {}

    // --- Range.createContextualFragment ---
    try {
        var origFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function(html) {
            record('createContextualFragment', String(html));
            return origFragment.call(this, html);
        };
    } catch(e) {}

    // --- DOMParser.parseFromString ---
    try {
        var origParser = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function(str, type) {
            record('DOMParser.parseFromString', String(str));
            return origParser.call(this, str, type);
        };
    } catch(e) {}

    // --- location.href setter ---
    // Catches both location.href = x and bare location = x assignments,
    // since Chrome routes both through the Location.prototype.href setter.
    try {
        var hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        if (hrefDesc && hrefDesc.set) {
            Object.defineProperty(Location.prototype, 'href', {
                get: hrefDesc.get,
                set: function(v) { record('location.href', String(v)); hrefDesc.set.call(this, v); },
                configurable: true, enumerable: true
            });
        }
    } catch(e) {}

    // --- Element.prototype.setAttribute (event-handler attribute names) ---
    // Catches el.setAttribute('onerror', ...) and setAttribute('onload', ...)
    // which bypass innerHTML-based sinks. Covers HTML and SVG elements
    // (SVGElement inherits from Element).
    try {
        var origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
            // Keep in sync with pkg/internal/xsspatterns.EventHandlerAttrRe ((?i)^on\w+$)
            if (typeof name === 'string' && /^on\w+$/i.test(name)) {
                record('setAttribute(' + String(name).toLowerCase() + ')', String(value));
            }
            return origSetAttr.call(this, name, value);
        };
    } catch(e) {}

    // --- history.pushState / replaceState ---
    // SPA routers navigate via the History API; location.href is
    // LegacyUnforgeable in Chrome (no interceptable prototype accessor),
    // so these two are the reliable SPA navigation sinks.
    try {
        var origPush = History.prototype.pushState;
        History.prototype.pushState = function(state, title, url) {
            if (url != null) { record('history.pushState', String(url)); }
            return origPush.apply(this, arguments);
        };
        var origHReplace = History.prototype.replaceState;
        History.prototype.replaceState = function(state, title, url) {
            if (url != null) { record('history.replaceState', String(url)); }
            return origHReplace.apply(this, arguments);
        };
    } catch(e) {}

    // Expose results
    window.__xsscan_hooks = sinks;
})();
