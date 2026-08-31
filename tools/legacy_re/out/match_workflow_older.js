export const meta = {
  name: 'nmsretro-anchor-match-older',
  description: 'Port 1.38-located string-less functions to 1.24/1.13/1.09.1 by decompiler-in-the-loop matching against each build\'s copy of the same anchor',
  phases: [
    { title: 'Match', detail: 'one agent per older build' },
    { title: 'Verify', detail: 'adversarial re-check per build' },
  ],
}

const TOOLS = "E:/Sync/No Man's Sky/NMSRetroPy/tools/legacy_re"

const MATCH_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    matches: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { target: { type: 'string' }, va: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] }, evidence: { type: 'string' } },
      required: ['target', 'va', 'confidence', 'evidence'] } },
    unresolved: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { target: { type: 'string' }, reason: { type: 'string' } }, required: ['target', 'reason'] } },
  },
  required: ['matches', 'unresolved'],
}
const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: { verdicts: { type: 'array', items: { type: 'object', additionalProperties: false,
    properties: { target: { type: 'string' }, va: { type: 'string' }, confirmed: { type: 'boolean' }, reason: { type: 'string' } },
    required: ['target', 'va', 'confirmed', 'reason'] } } },
  required: ['verdicts'],
}

function matchPrompt(build, targets) {
  return `You are reverse-engineering the No Man's Sky ${build} build. Each target below was already
located in the newer 1.38 build; find its counterpart in ${build} (the builds are months
apart, so the function exists here in a very similar form, hanging off the same mapped anchor).

Working directory: ${TOOLS}
Get your dossier slices (4.13 profile + this build's anchor body + size-banded candidate bodies):

    cd "${TOOLS}" && python fleet_slice.py ${build} ${targets.map(t => `'${t}'`).join(' ')}

For EACH target pick the ${build} candidate address that IS the function, matching on
parameter count, return kind, size ballpark (legacy drifts 0.5x-2x), the callee/behaviour
fingerprint, and how the anchor body uses the result. If no candidate matches (older builds
inline even more aggressively), return it unresolved with a concrete reason. A WRONG address
corrupts the data — only emit a va that appears verbatim in the candidate list, and never guess.

Return matches (target, va, confidence, evidence) and unresolved (target, reason).`
}
function verifyPrompt(build, targets, match) {
  const proposed = (match?.matches || []).map(m => `${m.target} = ${m.va} (${m.confidence}: ${m.evidence})`).join('\n')
  if (!proposed) return null
  return `Adversarial verifier for NMS ${build} reverse-engineering matches. Proposed:

${proposed}

Re-derive: cd "${TOOLS}" && python fleet_slice.py ${build} ${targets.map(t => `'${t}'`).join(' ')}
For each, try to REFUTE by checking size/signature/behaviour against the 4.13 profile. Confirm
only if clearly correct; default confirmed=false when uncertain or if it looks inlined. Return a verdict per match.`
}

const jobs = args.jobs
const results = await pipeline(
  jobs,
  (job) => agent(matchPrompt(job.build, job.targets), { schema: MATCH_SCHEMA, phase: 'Match', label: `match:${job.build}`, effort: 'high' }).then(match => ({ job, match })),
  (r) => {
    const vp = verifyPrompt(r.job.build, r.job.targets, r.match)
    if (!vp) return { ...r, verify: { verdicts: [] } }
    return agent(vp, { schema: VERIFY_SCHEMA, phase: 'Verify', label: `verify:${r.job.build}`, effort: 'high' }).then(verify => ({ ...r, verify }))
  }
)

const confirmed = {}, unresolved = {}
for (const r of results.filter(Boolean)) {
  const b = r.job.build
  confirmed[b] = confirmed[b] || {}; unresolved[b] = unresolved[b] || {}
  const ok = new Set((r.verify?.verdicts || []).filter(v => v.confirmed).map(v => `${v.target}@${v.va}`))
  for (const m of (r.match?.matches || [])) if (ok.has(`${m.target}@${m.va}`)) confirmed[b][m.target] = m.va
  for (const u of (r.match?.unresolved || [])) unresolved[b][u.target] = u.reason
}
log(`confirmed: ${Object.entries(confirmed).map(([b, m]) => `${b}:${Object.keys(m).length}`).join(' ')}`)
return { confirmed, unresolved }
