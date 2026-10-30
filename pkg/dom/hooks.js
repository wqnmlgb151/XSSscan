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
    // Distinguishes "no more hits were recorded" from "recording stopped at the cap".
    // The cap exists to bound memory; treating a full buffer as "no other sinks" would
    // be a false negative, so overflow is reported rather than inferred.
    var overflowed = false;
    // A script may remove its own element before the observation check. Keep
    // a permanent record of executable DOM content, including removed nodes.
    window.__xsscan_hasExecutableContent = false;
    var inspectedNodes = new WeakSet();
    function executableNode(node) {
        if (!node || node.nodeType !== 1 || inspectedNodes.has(node)) { return false; }
        inspectedNodes.add(node);
        if (node.matches('script,iframe,frame,object,embed,applet,meta[http-equiv],link[rel="import"]')) { return true; }
        for (var attr of node.attributes) {
            if (/^on/i.test(attr.name) || /^\s*javascript:/i.test(attr.value)) { return true; }
        }
        for (var child of node.querySelectorAll('*')) {
            if (inspectedNodes.has(child)) { continue; }
            inspectedNodes.add(child);
            if (executableNodeShallow(child)) { return true; }
        }
        return false;
    }
    function executableNodeShallow(node) {
        if (node.matches('script,iframe,frame,object,embed,applet,meta[http-equiv],link[rel="import"]')) { return true; }
        for (var attr of node.attributes) {
            if (/^on/i.test(attr.name) || /^\s*javascript:/i.test(attr.value)) { return true; }
        }
        return false;
    }
    try {
        new MutationObserver(function(records, observer) {
            if (window.__xsscan_hasExecutableContent) { observer.disconnect(); return; }
            for (var mutation of records) {
                if (mutation.type === 'attributes' &&
                    (/^on/i.test(mutation.attributeName) || executableNodeShallow(mutation.target))) {
                    window.__xsscan_hasExecutableContent = true; observer.disconnect(); return;
                }
                for (var node of [...mutation.addedNodes, ...mutation.removedNodes]) {
                    if (executableNode(node)) { window.__xsscan_hasExecutableContent = true; observer.disconnect(); return; }
                }
            }
        }).observe(document, {subtree:true, childList:true, attributes:true});
    } catch(e) { window.__xsscan_hasExecutableContent = true; }

    var MARKER = '__MARKER_PLACEHOLDER__';
    if (!MARKER || MARKER.length < 6) { return; }

    // hookStatus records whether each interception point was actually installed.
    // The presence of window.__xsscan_hooks proves only that this script ran; a hook
    // whose installation threw is a blind spot, and one that is reported can be
    // reasoned about while one that is assumed away cannot.
    var hookStatus = {};
    function installed(name) { hookStatus[name] = true; }

    // record captures what a sink received, centred on the marker.
    //
    // The previous version stored a prefix of the value, which loses the marker
    // entirely whenever it sits past the cut and loses the surrounding bytes that
    // identify the context the marker landed in. The window is therefore taken around
    // the marker, and the true position and length travel with it so a reader never
    // has to infer them from the snippet.
    var MAX_FRAMES = 4;
    // callerFrames captures where the sink was called from.
    //
    // The stack is read only when a hit is recorded, never for ordinary DOM calls: a
    // stack capture costs far more than the interception itself, and an unfired hook
    // has nothing to locate. Frames belonging to this instrumentation are dropped so
    // the first reported frame is the page's own code, which is the whole point —
    // a static script offset identifies a region of a file, whereas a call site
    // identifies the expression that ran.
    //
    // File and line are reliable when present; a frame without a usable location is
    // reported as 'unknown' rather than omitted, so a missing location is never
    // mistaken for a call site that was found.
    function callerFrames() {
        var raw;
        try { throw new Error(); } catch (e) { raw = e.stack || ''; }
        if (!raw) { return []; }
        var lines = raw.split('\n');
        var frames = [];
        for (var i = 0; i < lines.length && frames.length < MAX_FRAMES; i++) {
            var line = lines[i];
            if (line.indexOf('callerFrames') !== -1) { continue; }
            if (line.indexOf('record') !== -1 && line.indexOf('at ') !== -1) { continue; }
            var m = /([^\s()]+):(\d+):(\d+)/.exec(line);
            if (m) {
                frames.push({file: m[1], line: parseInt(m[2], 10), column: parseInt(m[3], 10)});
                continue;
            }
            // A frame exists but its location could not be read: keep it, labelled.
            if (/^\s*at /.test(line)) { frames.push({file: 'unknown', line: 0, column: 0}); }
        }
        return frames;
    }

    function record(sinkName, value) {
        if (sinks.length >= 100) { overflowed = true; return; }
        if (!value || typeof value !== 'string') { return; }
        if (value.length < MARKER.length) { return; }
        var at = value.indexOf(MARKER);
        if (at === -1) { return; }
        var before = 80, after = 240;
        var start = at - before; if (start < 0) { start = 0; }
        var end = at + MARKER.length + after; if (end > value.length) { end = value.length; }
        sinks.push({
            sink: sinkName,
            value: value.substring(start, end),
            value_length: value.length,
            marker_at: at,
            window_start: start,
            window_end: end,
            window_truncated: (start > 0 || end < value.length),
            frames: callerFrames()
        });
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
            installed('innerHTML');
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
            installed('outerHTML');
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
        installed('document.write');
    } catch(e) {}

    // --- Element.insertAdjacentHTML ---
    try {
        var origInsert = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(pos, html) {
            record('insertAdjacentHTML', html);
            return origInsert.call(this, pos, html);
        };
        installed('insertAdjacentHTML');
    } catch(e) {}

    // --- eval ---
    //
    // KNOWN LIMITATION, deliberately not papered over: a wrapper CANNOT preserve
    // direct-eval semantics. `eval(code)` written inside a function is a direct eval
    // that sees that function's lexical scope, but the moment the call is routed
    // through a property (`window.eval(code)`) it becomes an indirect eval that runs
    // in global scope. There is no wrapper expressible in JavaScript that keeps
    // directness, so any hit recorded here comes from a page whose eval calls this
    // instrumentation already altered.
    //
    // The hook is kept because an eval that does run still carries the marker, and
    // dropping it would lose real coverage; but evidence from this sink is weaker than
    // evidence from a sink whose wrapper is transparent, and it is labelled as such in
    // the report rather than being presented as equivalent.
    try {
        var origEval = window.eval;
        window.eval = function(code) { record('eval', String(code)); return origEval(code); };
        installed('eval');
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
        installed('Function');
    } catch(e) {}

    // --- setTimeout / setInterval (string form) ---
    try {
        var origST = window.setTimeout;
        window.setTimeout = function(fn, delay) {
            if (typeof fn === 'string') { record('setTimeout', fn); }
            return origST.apply(this, arguments);
        };
        var origSI = window.setInterval;
        window.setInterval = function(fn, delay) {
            if (typeof fn === 'string') { record('setInterval', fn); }
            return origSI.apply(this, arguments);
        };
        installed('setTimeout/setInterval');
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
        if (origAssign || origReplace) { installed('location.assign/replace'); }
    } catch(e) {}

    // Cookie writes are source state, not JavaScript execution sinks.

    // --- Range.createContextualFragment ---
    try {
        var origFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function(html) {
            record('createContextualFragment', String(html));
            return origFragment.call(this, html);
        };
        installed('createContextualFragment');
    } catch(e) {}

    // --- DOMParser.parseFromString ---
    try {
        var origParser = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function(str, type) {
            record('DOMParser.parseFromString', String(str));
            return origParser.call(this, str, type);
        };
        installed('DOMParser.parseFromString');
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
            installed('location.href');
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
        installed('setAttribute');
    } catch(e) {}

    // History changes are navigation state, not JavaScript execution sinks.

    // Expose results. hookStatus lets a consumer distinguish a complete
    // instrumentation set from one with blind spots.
    window.__xsscan_hooks = sinks;
    window.__xsscan_hook_status = hookStatus;
    window.__xsscan_hooks_overflowed = overflowed;
})();
