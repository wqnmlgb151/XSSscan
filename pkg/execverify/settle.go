package execverify

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"golang.org/x/net/html"
)

// Inertness is stronger than an empty timer queue: any executable content
// retains the full observation window, including rAF/message/timer callbacks.
const verificationActivityScript = `(() => {
 let executable=false;
 Object.defineProperty(window,'__xsscan_verifyExecutable',{get:()=>executable,configurable:false});
 const seen=new WeakSet();
 function shallow(node) {
  if(node.namespaceURI!=='http://www.w3.org/1999/xhtml')return true;
  if(node.matches('script,template,noscript,iframe,frame,object,embed,applet,meta[http-equiv],link[rel="import"]'))return true;
  return [...node.attributes].some(a=>/^on/i.test(a.name)||/^[\s\u0000-\u0020]*javascript:/i.test(a.value));
 }
 function inspect(node) {
  if(!node||node.nodeType!==1||seen.has(node))return false;
  seen.add(node);
  if(shallow(node))return true;
  for(const child of node.querySelectorAll('*')) {
   if(seen.has(child))continue;
   seen.add(child);if(shallow(child))return true;
  }
  return false;
 }
 try {
  new MutationObserver((records,observer)=>{
   if(records.length>1024)executable=true;
   try {for(const mutation of records) {
    if(mutation.type==='attributes'&&shallow(mutation.target))executable=true;
    for(const node of [...mutation.addedNodes,...mutation.removedNodes])if(inspect(node))executable=true;
    if(executable)break;
   }
   }catch(e){executable=true;}
   if(executable)observer.disconnect();
  }).observe(document,{subtree:true,childList:true,attributes:true});
 }catch(e){executable=true;}
})()`

type verificationActivity struct {
	document         network.RequestID
	decodedBytes     int64
	dataObserved     bool
	documentFinished bool
	sourceInert      bool
	unsafe           bool
	htmlDocument     bool
	mu               sync.Mutex
	pending          map[network.RequestID]bool
	last             time.Time
	changed          chan struct{}
	overflow         bool
	fullWindow       bool
}

func (a *verificationActivity) observe(event any) {
	a.mu.Lock()
	switch e := event.(type) {
	case *network.EventResponseReceived:
		if e.Type != network.ResourceTypeDocument {
			a.mu.Unlock()
			return
		}
		if a.document != "" && a.document != e.RequestID {
			a.unsafe = true
		}
		a.document = e.RequestID
		if e.Response == nil {
			a.unsafe = true
		} else {
			a.htmlDocument = strings.EqualFold(e.Response.MimeType, "text/html")
			for name := range e.Response.Headers {
				if strings.EqualFold(name, "Refresh") {
					a.unsafe = true
				}
			}
		}
	case *network.EventRequestWillBeSent:
		if len(a.pending) < 4096 {
			a.pending[e.RequestID] = true
		} else {
			a.overflow = true
		}
	case *network.EventDataReceived:
		if e.RequestID == a.document {
			a.dataObserved = true
			if e.DataLength < 0 || a.decodedBytes > 256*1024-int64(e.DataLength) {
				a.unsafe = true
			} else {
				a.decodedBytes += int64(e.DataLength)
			}
		}
	case *network.EventLoadingFinished:
		if e.RequestID == a.document {
			a.documentFinished = true
		}
		delete(a.pending, e.RequestID)
	case *network.EventLoadingFailed:
		delete(a.pending, e.RequestID)
	default:
		a.mu.Unlock()
		return
	}
	a.last = time.Now()
	a.mu.Unlock()
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

func (a *verificationActivity) wait(ctx context.Context, dialogs <-chan dialogInfo) (*dialogInfo, error) {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	checkInert := !a.fullWindow
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case d := <-dialogs:
			return &d, nil
		case <-deadline.C:
			return nil, nil
		case <-tick.C:
		case <-a.changed:
		}
		if !checkInert {
			continue
		}
		a.mu.Lock()
		quiet := a.sourceInert && !a.unsafe && !a.overflow && len(a.pending) == 0 && time.Since(a.last) >= 80*time.Millisecond
		a.mu.Unlock()
		if !quiet {
			continue
		}
		var inert bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(`this.__xsscan_verifyExecutable === false`, &inert)); err != nil {
			return nil, err
		}
		if inert {
			return nil, nil
		}
		// The monotonic flag cannot become inert again. Unknown instrumentation also
		// retains the entire window instead of manufacturing an early safe verdict.
		checkInert = false
	}
}

func newVerificationActivity(ctx context.Context) *verificationActivity {
	return &verificationActivity{pending: make(map[network.RequestID]bool), last: time.Now(), changed: make(chan struct{}, 1), fullWindow: browser.FullVerificationWindow(ctx)}
}

// Browser response bytes are checked outside the target's JavaScript realm.
// A live DOM observer alone is not evidence of inertness on an untrusted page.
func (a *verificationActivity) inspectDocument(ctx context.Context) {
	a.mu.Lock()
	id := a.document
	eligible := a.sourceEligible()
	a.mu.Unlock()
	if !eligible {
		return
	}
	var body []byte
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		body, err = network.GetResponseBody(id).Do(ctx)
		return err
	}))
	if err != nil || len(body) > 256*1024 {
		return
	}
	inert := inertVerificationDocument(body)
	a.mu.Lock()
	a.sourceInert = inert
	a.mu.Unlock()
}

func inertVerificationDocument(body []byte) bool {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			return z.Err() == io.EOF
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := z.Token()
		switch token.Data {
		case "html", "head", "body", "title", "div", "span", "p", "a", "b", "i", "u", "s", "strong", "em", "small", "big", "br", "hr", "pre", "code", "blockquote", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header", "footer", "nav", "main", "aside", "form", "input", "textarea", "button", "label", "select", "option", "optgroup", "fieldset", "legend", "img", "link":
		default:
			return false
		}
		for _, attr := range token.Attr {
			if strings.HasPrefix(attr.Key, "on") || attr.Key == "srcdoc" || attr.Key == "shadowrootmode" {
				return false
			}
			value := strings.Map(func(c rune) rune {
				if c <= 32 {
					return -1
				}
				return c
			}, strings.ToLower(attr.Val))
			if strings.Contains(value, "javascript:") || token.Data == "link" && attr.Key == "rel" && strings.Contains(value, "import") {
				return false
			}
		}
	}
}

// Called under mu: decoded CDP data accounting must be complete before copying
// a response body; Content-Length and compressed wire size are insufficient.
func (a *verificationActivity) sourceEligible() bool {
	return !a.unsafe && a.htmlDocument && a.document != "" && a.documentFinished && a.dataObserved && a.decodedBytes <= 256*1024
}
