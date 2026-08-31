export const meta = {
  name: 'nmsretro-anchor-match',
  description: 'Locate string-less legacy functions in NMS 1.38 by decompiler-in-the-loop matching, then adversarially verify',
  phases: [
    { title: 'Match', detail: 'one agent per batch reads dossier slices and proposes 1.38 addresses' },
    { title: 'Verify', detail: 'adversarial re-check of each proposed match' },
  ],
}

const TOOLS = "E:/Sync/No Man's Sky/NMSRetroPy/tools/legacy_re"

const MATCH_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    matches: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          target: { type: 'string' },
          va_138: { type: 'string', description: '0x-prefixed 1.38 address from the candidate list' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          evidence: { type: 'string', description: 'the specific decompiler signals that identify it' },
        },
        required: ['target', 'va_138', 'confidence', 'evidence'],
      },
    },
    unresolved: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          target: { type: 'string' },
          reason: { type: 'string', description: 'inlined into <fn> / fused with <family> / folded with <sib> / no matching shape' },
        },
        required: ['target', 'reason'],
      },
    },
  },
  required: ['matches', 'unresolved'],
}

const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          target: { type: 'string' },
          va_138: { type: 'string' },
          confirmed: { type: 'boolean' },
          reason: { type: 'string' },
        },
        required: ['target', 'va_138', 'confirmed', 'reason'],
      },
    },
  },
  required: ['verdicts'],
}

function matchPrompt(batch) {
  return `You are reverse-engineering the No Man's Sky 1.38 build, locating upstream functions that
have NO distinctive strings (so string search failed) by reading Ghidra decompilation.

Working directory: ${TOOLS}
Run this to get your dossier slices (it prints, per target, the 4.13 profile and the mapped
1.38 anchor's decompiled body plus candidate callees with their decompiled bodies):

    cd "${TOOLS}" && python fleet_slice.py ${batch.map(t => `'${t}'`).join(' ')}

For EACH target, decide which candidate 1.38 address (from the printed candidate list) IS
that function, or that it is not separately present in this build.

How to identify a match (need at least two independent signals for confidence high):
- Size: the candidate size is in the same ballpark as the 4.13 size (legacy drifts, so a
  ratio of 0.5x-2x is normal; wildly off is a no).
- Shape: the candidate's decompiled signature matches the 4.13 signature — parameter count,
  return kind (pointer / float / bool / void), struct-return.
- Behaviour: the candidate's body and its callees match what the function does in 4.13
  (the printed "4.13 distinctive callees" and signature tell you). E.g. a getter that
  returns this+offset after one call; a giver that constructs a manager then calls a
  reward function; a recursive tree-walk that calls itself or the shared find helper.
- Context: the anchor's own body shows how it uses each call's result — match that to the
  target's role.

CRITICAL HONESTY: the 2016-2017 MSVC inlined many small accessors into their one caller,
/OPT:ICF folded identical siblings, and some modern helpers did not exist yet (the code was
monolithic). When no candidate genuinely matches, return the target under "unresolved" with
a concrete reason (e.g. "inlined into the anchor body", "fused with the Get<Type> accessor
family", "no callee of matching shape/size"). A WRONG address is far worse than an honest
unresolved — the merge step trusts your address. Never pad with guesses; only emit a match
whose va appears verbatim in the candidate list.

Return matches (target, va_138, confidence, evidence) and unresolved (target, reason).`
}

function verifyPrompt(batch, match) {
  const proposed = (match?.matches || []).map(m => `${m.target} = ${m.va_138} (${m.confidence}: ${m.evidence})`).join('\n')
  if (!proposed) return null
  return `You are an adversarial verifier for reverse-engineering matches in the NMS 1.38 build.
Another analyst proposed these function identifications:

${proposed}

Working directory: ${TOOLS}
Re-derive the evidence yourself: cd "${TOOLS}" && python fleet_slice.py ${batch.map(t => `'${t}'`).join(' ')}

For each proposed match, try to REFUTE it. Check the candidate's size, decompiled signature
(param count / return kind), and behaviour against the 4.13 profile printed in the slice.
Confirm ONLY if the address is clearly the right function; if the shape or behaviour does not
fit, or a different candidate fits better, or the function looks inlined/fused, mark it
confirmed=false with the reason. Default to confirmed=false when genuinely uncertain.

Return a verdict for every proposed match.`
}

const batches = args.batches
const results = await pipeline(
  batches,
  (batch, _orig, i) => agent(matchPrompt(batch), { schema: MATCH_SCHEMA, phase: 'Match', label: `match:b${i}`, effort: 'high' }),
  (match, batch, i) => {
    const vp = verifyPrompt(batch, match)
    if (!vp) return { match, verify: { verdicts: [] } }
    return agent(vp, { schema: VERIFY_SCHEMA, phase: 'Verify', label: `verify:b${i}`, effort: 'high' })
      .then(verify => ({ match, verify }))
  }
)

// Confirmed = proposed AND verifier confirmed.
const confirmed = {}
const rejected = []
const unresolved = {}
for (const r of results.filter(Boolean)) {
  const m = r.match || r?.match?.match || {}
  const verify = r.verify || {}
  const okset = new Set((verify.verdicts || []).filter(v => v.confirmed).map(v => `${v.target}@${v.va_138}`))
  for (const mm of (m.matches || [])) {
    if (okset.has(`${mm.target}@${mm.va_138}`)) confirmed[mm.target] = { va_138: mm.va_138, evidence: mm.evidence }
    else rejected.push({ target: mm.target, va_138: mm.va_138, why: 'verifier refuted or dropped' })
  }
  for (const u of (m.unresolved || [])) unresolved[u.target] = u.reason
}

log(`confirmed ${Object.keys(confirmed).length}, rejected ${rejected.length}, unresolved ${Object.keys(unresolved).length}`)
return { confirmed, rejected, unresolved }
