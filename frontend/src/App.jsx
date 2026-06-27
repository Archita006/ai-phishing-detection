import { useState } from "react"
import axios from "axios"

const API = import.meta.env.VITE_API_URL || "https://ai-phishing-detection-5azt.onrender.com"
const getRiskColor = (score) => {
  if (score < 30) return { text: "text-emerald-400", label: "Safe" }
  if (score < 60) return { text: "text-yellow-400", label: "Suspicious" }
  return { text: "text-red-400", label: "Dangerous" }
}

function RiskMeter({ score }) {
  const { text, label } = getRiskColor(score)
  const circumference = 2 * Math.PI * 40
  const dash = (score / 100) * circumference
  return (
    <div className="flex flex-col items-center gap-3 py-6">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 100 100" className="w-full h-full">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="10"
            strokeDasharray={circumference} strokeDashoffset="0"
            transform="rotate(-90 50 50)" />
          <circle cx="50" cy="50" r="40" fill="none" strokeWidth="10"
            strokeDasharray={`${dash} ${circumference - dash}`}
            strokeDashoffset="0" strokeLinecap="round"
            transform="rotate(-90 50 50)"
            className={`transition-all duration-700 ${
              score < 30 ? "stroke-emerald-400" : score < 60 ? "stroke-yellow-400" : "stroke-red-400"
            }`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-2xl font-bold ${text}`}>{score}%</span>
          <span className="text-xs text-slate-400">risk</span>
        </div>
      </div>
      <span className={`text-sm font-semibold px-3 py-1 rounded-full border ${
        score < 30 ? "border-emerald-500 text-emerald-400"
        : score < 60 ? "border-yellow-500 text-yellow-400"
        : "border-red-500 text-red-400"
      }`}>{label}</span>
    </div>
  )
}

function RedFlags({ flags }) {
  if (!flags.length) return (
    <div className="flex items-center gap-2 text-emerald-400 text-sm py-2">
      <span>✓</span> No red flags detected
    </div>
  )
  return (
    <ul className="space-y-2">
      {flags.map((flag, i) => (
        <li key={i} className="flex items-start gap-2 text-sm text-red-300">
          <span className="mt-0.5 text-red-400">⚑</span> {flag}
        </li>
      ))}
    </ul>
  )
}

function HistoryItem({ item, onClick }) {
  const { text, label } = getRiskColor(item.risk_score)
  return (
    <button onClick={() => onClick(item)}
      className="w-full text-left px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors">
      <div className="flex justify-between items-center gap-2">
        <span className="text-xs text-slate-300 truncate">{item.url}</span>
        <span className={`text-xs font-semibold shrink-0 ${text}`}>{label}</span>
      </div>
      <div className="text-xs text-slate-500 mt-0.5">{item.risk_score}% risk</div>
    </button>
  )
}

function AIExplanation({ explanation, loading }) {
  if (loading) return (
    <div className="flex items-center gap-2 text-slate-400 text-sm py-2">
      <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3"
          strokeDasharray="31.4" strokeLinecap="round"/>
      </svg>
      Analyzing...
    </div>
  )
  if (!explanation) return null
  return (
    <div className="bg-indigo-950 border border-indigo-800 rounded-xl p-4">
      <p className="text-indigo-400 text-xs font-semibold uppercase tracking-widest mb-2">
        🔍 Analysis
      </p>
      <p className="text-sm text-slate-300 leading-relaxed">{explanation}</p>
    </div>
  )
}

async function getExplanation(data) {
  const res = await fetch(`${API}/explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: data.url,
      risk_score: data.risk_score,
      prediction: data.prediction,
      red_flags: data.red_flags,
      features: data.features
    })
  })
  const json = await res.json()
  return json.explanation
}

export default function App() {
  const [url, setUrl] = useState("")
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [history, setHistory] = useState([])
  const [aiExplanation, setAiExplanation] = useState("")
  const [aiLoading, setAiLoading] = useState(false)

  const analyze = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError("")
    setResult(null)
    setAiExplanation("")
    try {
      const res = await axios.post(`${API}/analyze`, { url })
      setResult(res.data)
      setHistory(prev => [res.data, ...prev].slice(0, 10))

      setAiLoading(true)
      const explanation = await getExplanation(res.data)
      setAiExplanation(explanation)
    } catch {
      setError("Could not connect to backend. Make sure it's running on port 8000.")
    } finally {
      setLoading(false)
      setAiLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <aside className="w-64 bg-slate-900 border-r border-slate-800 p-4 flex flex-col gap-3 shrink-0">
        <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">Scan History</h2>
        {history.length === 0
          ? <p className="text-xs text-slate-600">No scans yet</p>
          : history.map((item, i) => (
              <HistoryItem key={i} item={item} onClick={(r) => {
                setResult(r)
                setAiExplanation("")
              }} />
            ))
        }
      </aside>

      <main className="flex-1 flex flex-col items-center justify-start p-10 gap-8">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-white tracking-tight">🛡️ Phishing Detector</h1>
          <p className="text-slate-400 text-sm mt-1">AI-powered URL risk analysis</p>
        </div>

        <div className="w-full max-w-xl flex gap-2">
          <input
            className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            placeholder="Enter a URL to scan e.g. https://example.com"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && analyze()}
          />
          <button onClick={analyze} disabled={loading}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white px-5 py-3 rounded-xl text-sm font-semibold transition-colors">
            {loading ? "Scanning..." : "Scan"}
          </button>
        </div>

        {error && <p className="text-red-400 text-sm">{error}</p>}

        {result && (
          <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-5">
            <RiskMeter score={result.risk_score} />
            <AIExplanation explanation={aiExplanation} loading={aiLoading} />
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">Scanned URL</p>
              <p className="text-sm text-slate-300 break-all">{result.url}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Red Flags</p>
              <RedFlags flags={result.red_flags} />
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">URL Features</p>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(result.features)
                  .filter(([k]) => ['URLLength','DomainLength','IsHTTPS','NoOfSubDomain','HasObfuscation','IsDomainIP'].includes(k))
                  .map(([k, v]) => (
                    <div key={k} className="bg-slate-800 rounded-lg px-3 py-2">
                      <p className="text-xs text-slate-500">{k}</p>
                      <p className="text-sm font-medium text-white">{String(v)}</p>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}