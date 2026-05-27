// ─── GROQ AI UTILITY ────────────────────────────────────────────────────
// Model: llama-3.3-70b-versatile (fast, free tier, great for summarization)

const GROQ_API_KEY = import.meta.env.VITE_GROQ_API_KEY
const GROQ_MODEL   = 'llama-3.3-70b-versatile'
const GROQ_URL     = 'https://api.groq.com/openai/v1/chat/completions'

/**
 * Call the Groq API with a system prompt + user message.
 * Returns the assistant's reply as a plain string.
 */
export async function callGroq(systemPrompt, userMessage, maxTokens = 1024) {
  const res = await fetch(GROQ_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${GROQ_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userMessage  },
      ],
      max_tokens: maxTokens,
      temperature: 0.3,
    }),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err?.error?.message || `Groq API error ${res.status}`)
  }

  const data = await res.json()
  return data.choices?.[0]?.message?.content?.trim() || ''
}

// ─── FEATURE 1: AI Case Summarizer ──────────────────────────────────────
export async function generateCaseSummary({ caseData, iocs, findings, commands }) {
  const system = `You are a senior SOC analyst writing concise, professional incident summaries.
Write in plain English suitable for both technical analysts and non-technical management.
Structure: 1-2 sentence overview, then key findings, then recommended actions.
Be specific — mention actual IOC values, tactic names, and severity. No fluff.`

  const iocText = iocs.length
    ? iocs.map(i => `  - ${i.type.toUpperCase()} ${i.value} (risk: ${i.risk_level}${i.vt_result ? ', VT: ' + i.vt_result.verdict : ''})`).join('\n')
    : '  None logged'

  const findingText = findings.length
    ? findings.map(f => `  - [${f.severity}] ${f.title}${f.mitre_technique ? ' (' + f.mitre_technique + ')' : ''}: ${f.description || ''}`).join('\n')
    : '  None logged'

  const cmdText = commands.length
    ? commands.map(c => `  - ${c.command} (${c.purpose || 'no purpose noted'})`).join('\n')
    : '  None logged'

  const user = `Generate an executive incident summary for the following case:

CASE: ${caseData.title}
SEVERITY: ${caseData.severity}
STATUS: ${caseData.status}
ANALYST: ${caseData.analyst || 'Unassigned'}
MITRE TACTICS: ${caseData.mitre_tactics?.join(', ') || 'None'}
DESCRIPTION: ${caseData.description || 'None'}

INDICATORS OF COMPROMISE:
${iocText}

KEY FINDINGS:
${findingText}

COMMANDS RUN:
${cmdText}

NOTES: ${caseData.notes || 'None'}`

  return callGroq(system, user, 600)
}

// ─── FEATURE 2: IOC Context Explainer ───────────────────────────────────
export async function explainIOC({ value, type, risk_level, vt_result }) {
  const system = `You are a threat intelligence analyst. When given an IOC (indicator of compromise),
explain in 3-5 sentences:
1. What this IOC is and why it's relevant
2. Known threat campaigns, malware families, or threat actors it's associated with (if any)
3. Concrete recommended actions for the SOC team

Be direct and actionable. If you don't have specific intel, say so honestly and give general advice for that IOC type.
Format as plain paragraphs — no markdown headers, no bullet points.`

  const vtContext = vt_result
    ? `VirusTotal verdict: ${vt_result.verdict} (${vt_result.malicious} malicious, ${vt_result.suspicious} suspicious out of ${vt_result.total} engines).`
    : 'No VirusTotal data available.'

  const user = `Explain this IOC to a SOC analyst:
Type: ${type}
Value: ${value}
Risk Level: ${risk_level}
${vtContext}`

  return callGroq(system, user, 400)
}

// ─── FEATURE 3: Smart Severity Suggester ────────────────────────────────
export async function suggestSeverityAndTactics({ title, description }) {
  const system = `You are a SOC triage analyst. Given a security incident title and description,
respond with ONLY a JSON object — no explanation, no markdown, just raw JSON.

Format:
{
  "severity": "critical" | "high" | "medium" | "low",
  "tactics": ["Tactic Name 1", "Tactic Name 2"],
  "reason": "One sentence explaining your severity choice"
}

Use only official MITRE ATT&CK tactic names:
Reconnaissance, Resource Development, Initial Access, Execution, Persistence,
Privilege Escalation, Defense Evasion, Credential Access, Discovery,
Lateral Movement, Collection, Command and Control, Exfiltration, Impact`

  const user = `Incident title: ${title}
Description: ${description || 'No description provided'}`

  const raw = await callGroq(system, user, 300)

  // Strip markdown code fences if model wraps in ```json ... ```
  const cleaned = raw.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim()
  return JSON.parse(cleaned)
}
