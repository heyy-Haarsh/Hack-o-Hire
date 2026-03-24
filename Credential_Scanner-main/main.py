from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from datetime import datetime, timezone
import uuid
import time
import functools
from pydantic import BaseModel
from extractor        import extract_text
from patterns         import run_regex_scan, reload_patterns
from entropy          import run_entropy_scan
from ner_detector     import run_ner_scan
from llm_analyzer     import run_llm_scan, check_ollama_running
from context_analyzer import deduplicate, analyze_context
from risk_scorer      import calculate_risk

app = FastAPI(
    title="Credential Scanner",
    description="Hybrid credential scanner - regex + entropy + NER + LLM",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@functools.lru_cache(maxsize=1)
def _cached_ollama_check():
    return check_ollama_running()


def full_scan(text: str, source: str, filename: str = None) -> dict:
    timings = {}

    def track(stage_name, func, *args, **kwargs):
        print(f"[scan] Starting {stage_name}")
        started = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - started
        timings[stage_name] = round(elapsed, 3)
        print(f"[scan] Finished {stage_name} in {elapsed:.2f}s")
        return result

    raw = (
        track("regex_scan", run_regex_scan, text) +
        track("entropy_scan", run_entropy_scan, text) +
        track("ner_scan", run_ner_scan, text)
    )

    llm_available = False
    if llm_available:
        raw += track("llm_scan", run_llm_scan, text)
    else:
        timings["llm_scan"] = 0.0

    findings = track("deduplicate", deduplicate, raw)
    context = track("context_analysis", analyze_context, text, findings)
    result = track("risk_scoring", calculate_risk, findings, context)

    def count(tier):
        return sum(1 for f in findings if f["risk_tier"] == tier)

    return {
        "scan_id":            str(uuid.uuid4()),
        "timestamp":          datetime.now(timezone.utc).isoformat() + "Z",
        "source_type":        source,
        "filename":           filename,
        "total_findings":     len(findings),
        "critical_count":     count("Critical"),
        "high_count":         count("High"),
        "medium_count":       count("Medium"),
        "low_count":          count("Low"),
        "risk_score":         result["risk_score"],
        "risk_label":         result["risk_label"],
        "findings":           findings,
        "context_signals":    context,
        "human_summary":      result["human_summary"],
        "recommended_action": result["recommended_action"],
        "llm_available":      llm_available,
        "scan_timings":       timings,
    }


@app.get("/health")
def health():
    return {"status": "running", "version": "2.0.0",
            "llm": check_ollama_running()}


@app.post("/scan/text")
async def scan_text(text: str = Form(...)):
    if not text or len(text.strip()) < 5:
        raise HTTPException(400, "Text too short")
    return full_scan(text, source="plain_text")


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    request_start = time.perf_counter()
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large - max 25MB")
    try:
        print(
            f"[scan] Received file '{file.filename}' "
            f"({len(data) / 1024:.1f} KB)"
        )
        extract_start = time.perf_counter()
        text = extract_text(data, file.filename)
        extract_elapsed = time.perf_counter() - extract_start
        print(
            f"[scan] Text extraction completed in {extract_elapsed:.2f}s "
            f"with {len(text)} characters"
        )
    except Exception as ex:
        raise HTTPException(422, f"Could not read file: {ex}")
    if not text.strip():
        raise HTTPException(422, "No readable text found in file")
    ext = file.filename.rsplit(".", 1)[-1].lower()
    result = full_scan(text, source=f"file_{ext}", filename=file.filename)
    result["extraction_seconds"] = round(extract_elapsed, 3)
    result["total_processing_seconds"] = round(
        time.perf_counter() - request_start, 3
    )
    print(f"[scan] Request finished in {result['total_processing_seconds']:.2f}s")
    return result


@app.post("/admin/reload-patterns")
def reload():
    count = reload_patterns()
    return {"status": "reloaded", "patterns_loaded": count}


@app.get("/", response_class=HTMLResponse)
def frontend():
    return HTMLResponse(content=r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Credential Scanner</title>
<script src="https://unpkg.com/react@18/umd/react.development.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#1a1a1a;padding:32px 16px}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:22px;font-weight:700;color:#1a1a2e;margin-bottom:4px}
.sub{font-size:13px;color:#888;margin-bottom:28px}
.card{background:#fff;border:1px solid #e0e0e0;border-radius:12px;padding:28px;margin-bottom:20px}
.tabs{display:flex;gap:8px;margin-bottom:20px}
.tab{padding:8px 20px;border-radius:6px;border:1px solid #ccc;
     background:#f9f9f9;cursor:pointer;font-size:13px;font-weight:500;color:#555}
.tab.on{background:#1a1a2e;color:#fff;border-color:#1a1a2e}
textarea{width:100%;height:140px;padding:12px;border:1px solid #ddd;
         border-radius:8px;font-size:13px;resize:vertical;
         font-family:monospace;background:#fafafa}
textarea:focus{outline:none;border-color:#1a1a2e}
.drop{border:2px dashed #ccc;border-radius:8px;padding:36px;text-align:center;
      cursor:pointer;background:#fafafa;transition:border-color .15s}
.drop:hover{border-color:#1a1a2e;background:#f0f0f8}
.drop p{font-size:14px;color:#666;margin-bottom:4px}
.drop span{font-size:12px;color:#aaa}
.fname{margin-top:10px;font-size:13px;color:#1a1a2e;font-weight:600}
.btn{margin-top:18px;width:100%;padding:13px;background:#1a1a2e;color:#fff;
     border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn:hover:not(:disabled){opacity:.88}
.spin{text-align:center;padding:32px;font-size:14px;color:#888;line-height:1.7}
.banner{border-radius:12px;padding:22px 28px;margin-bottom:16px;
        display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:12px}
.banner.Clean   {background:#e8f5e9;border:1px solid #a5d6a7}
.banner.Low     {background:#e3f2fd;border:1px solid #90caf9}
.banner.Medium  {background:#fff8e1;border:1px solid #ffe082}
.banner.High    {background:#fff3e0;border:1px solid #ffcc80}
.banner.Critical{background:#fce4ec;border:1px solid #f48fb1}
.banner h2{font-size:18px;font-weight:700;margin-bottom:4px}
.banner p{font-size:13px;color:#555;max-width:520px}
.circle{width:76px;height:76px;border-radius:50%;display:flex;flex-direction:column;
        align-items:center;justify-content:center;border:3px solid;flex-shrink:0}
.circle .n{font-size:22px;font-weight:700}
.circle .l{font-size:10px;font-weight:500}
.Clean .circle{color:#388e3c}.Low .circle{color:#1976d2}
.Medium .circle{color:#f57f17}.High .circle{color:#e65100}
.Critical .circle{color:#c62828}
.abox{border-radius:8px;padding:12px 18px;font-size:13px;
      font-weight:500;margin-bottom:16px}
.abox.Clean   {background:#e8f5e9;color:#2e7d32}
.abox.Low     {background:#e3f2fd;color:#1565c0}
.abox.Medium  {background:#fff8e1;color:#e65100}
.abox.High    {background:#fff3e0;color:#bf360c}
.abox.Critical{background:#fce4ec;color:#b71c1c}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.pill{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600}
.pill.t{background:#ede7f6;color:#4527a0}.pill.c{background:#fce4ec;color:#b71c1c}
.pill.h{background:#fff3e0;color:#bf360c}.pill.m{background:#fff8e1;color:#e65100}
.pill.l{background:#e8f5e9;color:#2e7d32}
.layer{background:#fff;border:1px solid #e0e0e0;border-radius:12px;
       margin-bottom:12px;overflow:hidden}
.lhead{padding:14px 20px;display:flex;align-items:center;
       justify-content:space-between;cursor:pointer;
       background:#fafafa;border-bottom:1px solid #eee}
.lhead:hover{background:#f0f0f8}
.ltitle{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:600}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700}
.b1{background:#ede7f6;color:#4527a0}.b2{background:#fff8e1;color:#e65100}
.b3{background:#e0f2f1;color:#00695c}.b4{background:#fce4ec;color:#b71c1c}
.b5{background:#e8f5e9;color:#2e7d32}
.lcount{font-size:12px;color:#888}
.lbody{padding:16px 20px}
.finding{border:1px solid #eee;border-radius:8px;padding:14px;
         margin-bottom:10px;background:#fafafa}
.finding:last-child{margin-bottom:0}
.ftop{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.ftype{font-size:13px;font-weight:600;color:#1a1a2e}
.tier{padding:2px 10px;border-radius:10px;font-size:11px;font-weight:700}
.tier.Critical{background:#fce4ec;color:#b71c1c}
.tier.High    {background:#fff3e0;color:#bf360c}
.tier.Medium  {background:#fff8e1;color:#e65100}
.tier.Low     {background:#e8f5e9;color:#2e7d32}
.conf{font-size:11px;color:#aaa;margin-left:auto}
.fdesc{font-size:12px;color:#666;margin-bottom:6px}
.snippet{font-size:12px;font-family:monospace;background:#f0f0f0;
         padding:8px 10px;border-radius:6px;word-break:break-all;margin-bottom:6px}
.redacted{font-size:12px;color:#888}
.redacted code{background:#e8e8e8;padding:1px 6px;border-radius:4px;color:#444}
.empty{font-size:13px;color:#bbb;text-align:center;padding:14px 0}
.sgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.sig{padding:10px 14px;border-radius:8px;font-size:12px;font-weight:500;border:1px solid}
.sig.yes{background:#fce4ec;color:#b71c1c;border-color:#f48fb1}
.sig.no {background:#f5f5f5;color:#999;border-color:#e0e0e0}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.sig.yes .dot{background:#c62828}.sig.no .dot{background:#bbb}
.mult{margin-top:10px;padding:10px 14px;background:#fff8e1;border-radius:8px;
      font-size:13px;color:#e65100;font-weight:600}
.llm-off{font-size:13px;color:#e65100;padding:10px 14px;
         background:#fff8e1;border-radius:8px;margin-bottom:12px}
.again{margin-top:20px;padding:10px 28px;background:#fff;
       border:1px solid #1a1a2e;border-radius:8px;
       color:#1a1a2e;font-size:14px;font-weight:600;cursor:pointer}
.again:hover{background:#f0f0f8}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const { useState, useRef, useEffect } = React

const LAYER_COLORS = {
  regex:   {bg:'#ede7f6', color:'#4527a0'},
  entropy: {bg:'#fff8e1', color:'#e65100'},
  ner:     {bg:'#e0f2f1', color:'#00695c'},
  llm:     {bg:'#fce4ec', color:'#b71c1c'},
}

const SIG_LABELS = {
  has_urgency_language:          'Urgency / pressure language',
  has_internal_exposure_signals: 'Internal exposure signals',
  has_impersonation_signals:     'Bank impersonation signals',
  has_multiple_credential_types: 'Multiple credential types',
  has_attachment_reference:      'Attachment reference',
}

function FindingCard({ f }) {
  const layers = f.detected_by || [f.layer]
  return (
    <div className="finding">
      <div className="ftop">
        <span className="ftype">{f.credential_type.replace(/_/g,' ')}</span>
        <span className={`tier ${f.risk_tier}`}>{f.risk_tier}</span>
        <span className="conf">confidence {Math.round(f.confidence*100)}%</span>
      </div>

      <div style={{display:'flex',gap:6,marginBottom:8,flexWrap:'wrap'}}>
        {layers.map(l => (
          <span key={l} style={{
            padding:'2px 8px',borderRadius:10,fontSize:11,fontWeight:600,
            background: LAYER_COLORS[l]?.bg || '#f5f5f5',
            color:      LAYER_COLORS[l]?.color || '#555'
          }}>{l}</span>
        ))}
        {layers.length > 1 &&
          <span style={{padding:'2px 8px',borderRadius:10,fontSize:11,
            fontWeight:700,background:'#e8f5e9',color:'#2e7d32'}}>
            multi-layer confirmed
          </span>}
      </div>

      <div className="fdesc">{f.description}</div>
      {f.context_snippet && f.context_snippet !== 'N/A' &&
      <div className="snippet">{f.context_snippet}</div>}
{f.credential_type === 'phishing_intent' &&
  <div className="snippet" style={{background:'#fce4ec',color:'#b71c1c'}}>
    {f.description}
  </div>}
      <div className="redacted">
        Redacted: <code>{f.redacted_value}</code>
        {f.entropy_score !== undefined &&
          <span>&nbsp;|&nbsp;Entropy: <code>{f.entropy_score}</code></span>}
      </div>
    </div>
  )
}

function Layer({ badge, badgeClass, title, findings, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="layer">
      <div className="lhead" onClick={() => setOpen(o => !o)}>
        <div className="ltitle">
          <span className={`badge ${badgeClass}`}>{badge}</span>
          {title}
        </div>
        <div style={{display:'flex',alignItems:'center',gap:12}}>
          <span className="lcount">
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </span>
          <span style={{fontSize:12,color:'#aaa'}}>{open?'▲':'▼'}</span>
        </div>
      </div>
      {open && (
        <div className="lbody">
          {findings.length === 0
            ? <div className="empty">No findings from this layer</div>
            : findings.map((f,i) => <FindingCard key={i} f={f}/>)}
        </div>
      )}
    </div>
  )
}

function ContextLayer({ signals, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const keys = Object.keys(SIG_LABELS)
  const cats = (signals.credential_categories || []).join(', ') || 'none'
  return (
    <div className="layer">
      <div className="lhead" onClick={() => setOpen(o => !o)}>
        <div className="ltitle">
          <span className="badge b5">Context</span>
          Context Analysis
        </div>
        <div style={{display:'flex',alignItems:'center',gap:12}}>
          <span className="lcount">multiplier {signals.context_multiplier}x</span>
          <span style={{fontSize:12,color:'#aaa'}}>{open?'▲':'▼'}</span>
        </div>
      </div>
      {open && (
        <div className="lbody">
          <div className="sgrid">
            {keys.map(k => (
              <div key={k} className={`sig ${signals[k] ? 'yes' : 'no'}`}>
                <span className="dot"/>
                {SIG_LABELS[k]}
              </div>
            ))}
          </div>
          <div className="mult">
            Multiplier: {signals.context_multiplier}x
            &nbsp;|&nbsp;
            Multi-layer confirmed: {signals.multi_layer_confirmed_count || 0}
            &nbsp;|&nbsp;
            Categories: {cats}
          </div>
        </div>
      )}
    </div>
  )
}

function UploadForm({ onResult }) {
  const [tab, setTab] = useState('text')
  const [txt, setTxt] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingMsg, setLoadingMsg] = useState('')
  const [elapsedSec, setElapsedSec] = useState(0)
  const fileRef = useRef()

  useEffect(() => {
    if (!loading) {
      setElapsedSec(0)
      return
    }

    const timer = setInterval(() => {
      setElapsedSec(prev => prev + 1)
    }, 1000)

    return () => clearInterval(timer)
  }, [loading])

  useEffect(() => {
    if (!loading) {
      setLoadingMsg('')
      return
    }

    if (tab === 'file') {
      if (elapsedSec < 4) setLoadingMsg('Uploading file and extracting text...')
      else if (elapsedSec < 10) setLoadingMsg('Running regex, entropy, and NER checks...')
      else if (elapsedSec < 20) setLoadingMsg('Large PDFs can take longer. The scan is still in progress...')
      else setLoadingMsg('Still processing. Check the server console for per-stage progress logs.')
      return
    }

    if (elapsedSec < 4) setLoadingMsg('Scanning text across all layers...')
    else if (elapsedSec < 10) setLoadingMsg('Still working through the scan...')
    else setLoadingMsg('Longer than usual. Check the server console for stage timings.')
  }, [elapsedSec, loading, tab])

  async function scan() {
    setLoading(true)
    setElapsedSec(0)
    try {
      let res
      if (tab === 'text') {
        if (!txt.trim()) {
          alert('Paste some text first.')
          setLoading(false); return
        }
        const fd = new FormData()
        fd.append('text', txt)
        res = await fetch('/scan/text', { method:'POST', body:fd })
      } else {
        if (!file) {
          alert('Select a file first.')
          setLoading(false); return
        }
        const fd = new FormData()
        fd.append('file', file)
        res = await fetch('/scan/file', { method:'POST', body:fd })
      }
      const data = await res.json()
      if (!res.ok) {
        alert('Error: ' + (data.detail || 'unknown'))
        setLoading(false); return
      }
      onResult(data)
    } catch(e) {
      alert('Cannot connect to server. Is uvicorn running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <div className="tabs">
        <button className={`tab ${tab==='text'?'on':''}`}
          onClick={() => setTab('text')}>
          Paste email / text
        </button>
        <button className={`tab ${tab==='file'?'on':''}`}
          onClick={() => setTab('file')}>
          Upload file
        </button>
      </div>

      {tab === 'text' ? (
        <textarea
          value={txt}
          onChange={e => setTxt(e.target.value)}
          placeholder="Paste email content, headers, body - anything suspicious..."/>
      ) : (
        <div className="drop" onClick={() => fileRef.current.click()}>
          <p>Drop file here or click to browse</p>
          <span>Supports .eml | .pdf | .docx | .png | .jpg | .txt</span>
          <input ref={fileRef} type="file"
            accept=".eml,.pdf,.docx,.png,.jpg,.jpeg,.txt,.bmp,.tiff"
            style={{display:'none'}}
            onChange={e => setFile(e.target.files[0])}/>
          {file && <div className="fname">Selected: {file.name}</div>}
        </div>
      )}

      {loading
        ? <div className="spin">{loadingMsg}<br/><br/>Elapsed: {elapsedSec}s</div>
        : <button className="btn" onClick={scan}>Scan now</button>}
    </div>
  )
}

function Results({ data, onReset }) {
  const label = data.risk_label || 'Clean'
  const findings = data.findings || []

  const byLayer = {
    regex:   findings.filter(f => f.layer === 'regex'),
    entropy: findings.filter(f => f.layer === 'entropy'),
    ner:     findings.filter(f => f.layer === 'ner'),
    llm:     findings.filter(f => f.layer === 'llm'),
  }

  return (
    <div>
      <div className={`banner ${label}`}>
        <div>
          <h2>{label} Risk</h2>
          <p>{data.human_summary}</p>
        </div>
        <div className="circle">
          <span className="n">{data.risk_score}</span>
          <span className="l">/ 100</span>
        </div>
      </div>

      <div className={`abox ${label}`}>
        Recommended action: {data.recommended_action}
      </div>

      <div className="pills">
        <span className="pill t">Total: {data.total_findings}</span>
        <span className="pill c">Critical: {data.critical_count}</span>
        <span className="pill h">High: {data.high_count}</span>
        <span className="pill m">Medium: {data.medium_count}</span>
        <span className="pill l">Low: {data.low_count}</span>
      </div>

      {data.total_processing_seconds !== undefined &&
        <div className="llm-off" style={{marginTop:0}}>
          Processing time: {data.total_processing_seconds}s
          {data.extraction_seconds !== undefined &&
            ` | Extraction: ${data.extraction_seconds}s`}
        </div>}

      {!data.llm_available &&
        <div className="llm-off">
          LLM layer offline - run "ollama serve" in a separate terminal
          then make sure your local llama3 model is available
        </div>}

      <Layer badge="Layer 2" badgeClass="b1"
        title="Regex Pattern Scan (TruffleHog-style)"
        findings={byLayer.regex}
        defaultOpen={byLayer.regex.length > 0}/>

      <Layer badge="Layer 3" badgeClass="b2"
        title="Entropy Analysis"
        findings={byLayer.entropy}
        defaultOpen={byLayer.entropy.length > 0}/>

      <Layer badge="Layer 4" badgeClass="b3"
        title="Named Entity Recognition (NLTK)"
        findings={byLayer.ner}
        defaultOpen={byLayer.ner.length > 0}/>

      <Layer badge="Layer 5" badgeClass="b4"
        title="LLM Analysis (Ollama - llama3:latest)"
        findings={byLayer.llm}
        defaultOpen={byLayer.llm.length > 0}/>

      <ContextLayer
        signals={data.context_signals || {}}
        defaultOpen={true}/>

      <button className="again" onClick={onReset}>
        Scan another email
      </button>
    </div>
  )
}

function App() {
  const [result, setResult] = useState(null)
  return (
    <div className="wrap">
      <h1>Credential Scanner</h1>
      <p className="sub">
        Hybrid detection - Regex + Entropy + NER + LLM -
        running fully offline
      </p>
      {result
        ? <Results data={result} onReset={() => setResult(null)}/>
        : <UploadForm onResult={setResult}/>}
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>)
</script>
</body>
</html>
""")

class EmailScanRequest(BaseModel):
    text:    str
    subject: str = ""
    sender:  str = ""

@app.post("/analyze/email")
async def analyze_email_text(req: EmailScanRequest):
    """Plugin-compatible endpoint — scans email for exposed credentials."""
    full_text = f"Subject: {req.subject}\nFrom: {req.sender}\n\n{req.text}"
    if not full_text.strip():
        raise HTTPException(400, "Empty email")
    return full_scan(full_text, source="email")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
