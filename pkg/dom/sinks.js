// DOM XSS sink detection script — evaluated in-browser via chromedp.
// Returns a semicolon-separated list of sink categories the marker reached.
(function() {
	var marker = '{{MARKER}}';
	var sinks = [];

	// Cache outerHTML once — multiple checks below need it.
	var pageHTML = document.documentElement.outerHTML;

	// innerHTML sinks — marker rendered as HTML
	var all = document.querySelectorAll('*');
	for (var i = 0; i < all.length; i++) {
		if (all[i].innerHTML && all[i].innerHTML.indexOf(marker) !== -1) {
			sinks.push('innerHTML:' + all[i].tagName);
		}
	}

	// script content injection — marker inside <script> text
	if (document.body && document.body.innerHTML.indexOf(marker) !== -1) {
		var scripts = document.querySelectorAll('script');
		for (var j = 0; j < scripts.length; j++) {
			if (scripts[j].textContent && scripts[j].textContent.indexOf(marker) !== -1) {
				sinks.push('script_content');
			}
		}
	}

	// window.name transport — only if the page reads window.name
	if (window.name && window.name.indexOf(marker) !== -1 &&
		(pageHTML.indexOf('window.name') !== -1 || pageHTML.indexOf('window["name"]') !== -1)) {
		sinks.push('window.name');
	}

	// location-based sources — marker present in URL components
	if (location.hash && location.hash.indexOf(marker) !== -1) {
		sinks.push('location.hash');
	}
	if (location.search && location.search.indexOf(marker) !== -1) {
		sinks.push('location.search');
	}
	if (location.pathname && location.pathname.indexOf(marker) !== -1) {
		sinks.push('location.pathname');
	}

	// document.referrer — only if referrer is non-empty and contains marker
	if (document.referrer && document.referrer.indexOf(marker) !== -1) {
		sinks.push('document.referrer');
	}

	// inline event handler execution — marker-triggered handler actually fired
	if (document.body && document.body.getAttribute('data-' + marker + '-fired')) {
		sinks.push('inline_event_executed');
	}

	// javascript: protocol in href/src — marker reached a javascript: URL
	var links = document.querySelectorAll('a[href], area[href], iframe[src], embed[src]');
	for (var l = 0; l < links.length; l++) {
		var href = links[l].href || links[l].src;
		if (href && href.toLowerCase().indexOf('javascript:') !== -1 && href.indexOf(marker) !== -1) {
			sinks.push('javascript_protocol');
			break;
		}
	}

	// eval / Function / setTimeout / setInterval — dangerous sinks
	if (pageHTML.indexOf('eval(') !== -1 || pageHTML.indexOf('Function(') !== -1) {
		sinks.push('eval_or_Function');
	}
	if (pageHTML.indexOf('setTimeout(') !== -1 || pageHTML.indexOf('setInterval(') !== -1) {
		sinks.push('setTimeout_or_setInterval');
	}

	// Storage-based sources — marker read from localStorage/sessionStorage.
	// Detects patterns like: innerHTML = localStorage.getItem('key')
	if (pageHTML.indexOf('localStorage') !== -1) {
		try {
			for (var s = 0; s < localStorage.length; s++) {
				var key = localStorage.key(s);
				if (key && key.indexOf(marker) !== -1) {
					sinks.push('localStorage');
					break;
				}
			}
		} catch (e) { /* localStorage access may be denied */ }
	}
	if (pageHTML.indexOf('sessionStorage') !== -1) {
		try {
			for (var t = 0; t < sessionStorage.length; t++) {
				var sKey = sessionStorage.key(t);
				if (sKey && sKey.indexOf(marker) !== -1) {
					sinks.push('sessionStorage');
					break;
				}
			}
		} catch (e) { /* sessionStorage access may be denied */ }
	}

	// document.referrer / document.cookie — marker present in readable cookie
	if (document.cookie && document.cookie.indexOf(marker) !== -1) {
		sinks.push('document.cookie');
	}

	// postMessage — marker present in page source's message handler
	if (pageHTML.indexOf('postMessage') !== -1 || pageHTML.indexOf("addEventListener('message'") !== -1 || pageHTML.indexOf('addEventListener("message"') !== -1) {
		sinks.push('postMessage');
	}

	return sinks.join(';');
})()
