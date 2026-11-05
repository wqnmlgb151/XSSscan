"""Instrument an isolated checkout for stage timing and pprof, never the main tree."""

import argparse
from pathlib import Path
import re
import subprocess


HELPER = r'''package perfstage
import (
 "encoding/json"
 "os"
 "path/filepath"
 "runtime"
 "runtime/pprof"
 "sync"
 "time"
)
var mu sync.Mutex
var once sync.Once
type sample struct { Calls int; TotalMS float64; MaxMS float64 }
var samples = map[string]sample{}
var cpu *os.File
var directory string
var module = "startup"
func SetModule(name string) {mu.Lock();module=name;mu.Unlock()}
func init() {
 directory = os.Getenv("XSSCAN_PERF_DIR")
 if directory == "" { panic("XSSCAN_PERF_DIR required for instrumented binary") }
 if err := os.MkdirAll(directory, 0700); err != nil { panic(err) }
 var err error
 cpu, err = os.Create(filepath.Join(directory,"cpu.pprof")); if err != nil { panic(err) }
 if err = pprof.StartCPUProfile(cpu); err != nil { panic(err) }
 runtime.SetBlockProfileRate(1)
 runtime.SetMutexProfileFraction(1)
}
func Measure(name string) func() {
 mu.Lock(); name=module+"/"+name; mu.Unlock()
 start:=time.Now()
 return func() {
  ms:=float64(time.Since(start))/float64(time.Millisecond)
  mu.Lock(); defer mu.Unlock()
  value:=samples[name]; value.Calls++; value.TotalMS+=ms
  if ms>value.MaxMS {value.MaxMS=ms}; samples[name]=value
 }
}
func Close() { once.Do(func(){
 pprof.StopCPUProfile(); cpu.Close()
 for _, name:=range []string{"block","mutex","heap"} {
  f,err:=os.Create(filepath.Join(directory,name+".pprof")); if err!=nil {panic(err)}
  if err=pprof.Lookup(name).WriteTo(f,0);err!=nil {panic(err)};f.Close()
 }
 mu.Lock();defer mu.Unlock()
 data,err:=json.MarshalIndent(samples,"","  ");if err!=nil {panic(err)}
 if err=os.WriteFile(filepath.Join(directory,"stages.json"),data,0600);err!=nil {panic(err)}
}) }
func Exit(code int) { Close();os.Exit(code) }
'''


def instrument(root):
    """Only add timers to known functions; absent anchors fail the build preparation."""
    paths = {}

    def read(name):
        if name not in paths:
            paths[name] = (root / name).read_text(encoding="utf-8")
        return paths[name]

    def replace(name, before, after):
        text = read(name)
        if text.count(before) != 1:
            raise ValueError(f"expected one instrumentation anchor: {name}: {before}")
        paths[name] = text.replace(before, after, 1)

    functions = [
        ("pkg/ssrfguard/ssrfguard.go", "IsURLTargetAllowedContext", "dns_ssrf"),
        ("pkg/internal/chromedp/isolated.go", "NewIsolatedTabContext", "context_setup"),
        ("pkg/dom/settle.go", "wait", "page_observation"),
        ("pkg/dom/scanner.go", "Close", "browser_process_cleanup"),
        ("pkg/stored/scanner.go", "discoverTriggerURLs", "stored_discovery"),
        ("pkg/stored/scanner.go", "submitExchange", "stored_submit"),
        ("pkg/stored/evidence.go", "fetchObservation", "stored_fetch"),
        ("pkg/stored/evidence.go", "pollObservations", "stored_polling"),
    ]
    for name, function, stage in functions:
        text = read(name)
        pattern = r"(?m)^func (?:\([^\n]+\) )?" + function + r"\([^\n]*\{\n"
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1:
            raise ValueError(f"missing or ambiguous function {name}:{function}")
        pos = matches[0].end()
        paths[name] = text[:pos] + f'\tdefer perfstage.Measure("{stage}")()\n' + text[pos:]
    replace("pkg/dom/scanner.go", "s.browserOnce.Do(func() {\n",
            's.browserOnce.Do(func() {\n defer perfstage.Measure("browser_init")()\n')
    replace("pkg/dom/scanner.go", "defer func() {\n\t\ttabCancel()",
            'defer func() {\n defer perfstage.Measure("context_cleanup")()\n\t\ttabCancel()')
    replace("pkg/dom/replay_browser.go", "defer func() {\n\t\tcancelReplay()",
            'defer func() {\n defer perfstage.Measure("replay_context_cleanup")()\n\t\tcancelReplay()')
    replace("pkg/orchestrator/runner.go", "for _, kind := range r.plan.Types {",
            "for _, kind := range r.plan.Types {\n perfstage.SetModule(string(kind))")
    replace("pkg/internal/chromedp/guard.go", "return g, ext.ActionFunc(func(ctx context.Context) error {\n",
            'return g, ext.ActionFunc(func(ctx context.Context) error {\n defer perfstage.Measure("guard_setup")()\n')
    replace("pkg/internal/chromedp/guard.go", "err = continuation.Do(ctx)",
            'endContinue := perfstage.Measure("guard_cdp_continue"); err = continuation.Do(ctx); endContinue()')
    replace("pkg/stored/evidence.go", "timer := time.NewTimer(s.config.PollingInterval)",
            'endPollWait := perfstage.Measure("stored_poll_wait"); timer := time.NewTimer(s.config.PollingInterval)')
    replace("pkg/stored/evidence.go", "case <-timer.C:\n\t\t\t}",
            "case <-timer.C:\n\t\t\t}\n endPollWait()")
    replace("pkg/stored/evidence.go", "timer.Stop()", "timer.Stop(); endPollWait()")
    main = read("cmd/main.go")
    paths["cmd/main.go"] = main.replace("func main() {", "func main() {\n defer perfstage.Close()", 1).replace("os.Exit(", "perfstage.Exit(")
    for name, text in paths.items():
        text = text.replace("import (", 'import (\n "github.com/wqnmlgb151/XSSscan/pkg/perfstage"', 1)
        (root / name).write_text(text, encoding="utf-8")
    helper = root / "pkg/perfstage"
    helper.mkdir(exist_ok=False)
    (helper / "profile.go").write_text(HELPER, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.checkout.resolve(strict=True)
    if root == Path.cwd().resolve() or not (root / ".git").is_file():
        parser.error("a separate git worktree is required")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
        parser.error("profiling checkout must be clean")
    instrument(root)
    subprocess.run([args.go, "build", "-o", str(args.output.resolve()), "./cmd"], cwd=root, check=True)


if __name__ == "__main__":
    main()
