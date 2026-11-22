const SEVERITY_ORDER = {
  critical: 5,
  major: 4,
  minor: 3,
  warning: 2,
  info: 1,
};

const MINUTE = 60 * 1000;

function toMs(value) {
  if (value === null || value === undefined) return null;
  const ms = new Date(value).getTime();
  if (Number.isNaN(ms)) throw new Error(`invalid timestamp: ${value}`);
  return ms;
}

function iso(ms) {
  return ms === null || ms === undefined ? null : new Date(ms).toISOString();
}

function severityRank(severity) {
  return SEVERITY_ORDER[severity] ?? 0;
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  const aE = aEnd === null ? Infinity : aEnd;
  const bE = bEnd === null ? Infinity : bEnd;
  return aStart < bE && bStart < aE;
}

class UnionFind {
  constructor() {
    this.parent = new Map();
  }

  find(x) {
    if (!this.parent.has(x)) this.parent.set(x, x);
    let root = x;
    while (this.parent.get(root) !== root) root = this.parent.get(root);
    let node = x;
    while (this.parent.get(node) !== node) {
      const next = this.parent.get(node);
      this.parent.set(node, root);
      node = next;
    }
    return root;
  }

  union(a, b) {
    this.parent.set(this.find(a), this.find(b));
  }
}

function matchLabels(matchers, incident) {
  return Object.entries(matchers).every(([key, expected]) => {
    if (key === 'fingerprint') return incident.fingerprint === expected;
    if (key === 'source') return incident.source === expected;
    if (key === 'severity') return incident.severity === expected;
    return incident.labels?.[key] === expected;
  });
}

function policyMatches(policy, incident) {
  const match = policy.match ?? {};
  if (match.source && match.source !== incident.source) return false;
  if (match.severities && !match.severities.includes(incident.severity)) return false;
  if (match.labels) {
    for (const [key, value] of Object.entries(match.labels)) {
      if (incident.labels?.[key] !== value) return false;
    }
  }
  return true;
}

function resolveOncall(oncall, group, atMs) {
  const entries = oncall[group]?.schedule ?? [];
  for (const entry of entries) {
    const from = toMs(entry.from);
    const to = entry.to === null || entry.to === undefined ? Infinity : toMs(entry.to);
    if (from <= atMs && atMs < to) return entry.user;
  }
  return null;
}

export function analyze(input) {
  const now = toMs(input.now) ?? Date.now();
  const raceWindowMs = (input.raceWindowMinutes ?? 5) * MINUTE;
  const evidence = new Map();
  const conflicts = [];

  const addEvidence = (id, message) => {
    if (!evidence.has(id)) evidence.set(id, []);
    evidence.get(id).push(message);
  };

  // 1. Deduplicate strictly by fingerprint. Label similarity is never used,
  //    so independent faults with look-alike labels stay separate.
  const incidents = new Map();
  const duplicates = [];
  for (const event of input.events ?? []) {
    const existing = incidents.get(event.fingerprint);
    if (existing) {
      existing.events.push(event.id);
      existing.startsAtMs = Math.min(existing.startsAtMs, toMs(event.startsAt));
      const endMs = toMs(event.endsAt);
      existing.endsAtMs =
        existing.endsAtMs === null || endMs === null
          ? null
          : Math.max(existing.endsAtMs, endMs);
      duplicates.push({ event: event.id, mergedInto: existing.fingerprint });
      addEvidence(
        existing.fingerprint,
        `event ${event.id} is an exact-fingerprint duplicate and was merged`,
      );
      continue;
    }
    incidents.set(event.fingerprint, {
      fingerprint: event.fingerprint,
      source: event.source,
      severity: event.severity,
      labels: event.labels ?? {},
      startsAtMs: toMs(event.startsAt),
      endsAtMs: toMs(event.endsAt),
      events: [event.id],
    });
    addEvidence(
      event.fingerprint,
      `event ${event.id} opened incident (source=${event.source}, severity=${event.severity})`,
    );
  }

  // 2. Root-cause graph: upstream -> downstream edges over fingerprints.
  const downstreamOf = new Map();
  const upstreamOf = new Map();
  const uf = new UnionFind();
  for (const fp of incidents.keys()) uf.find(fp);
  for (const edge of input.rootCauses ?? []) {
    if (!incidents.has(edge.upstream) || !incidents.has(edge.downstream)) continue;
    if (!downstreamOf.has(edge.upstream)) downstreamOf.set(edge.upstream, []);
    downstreamOf.get(edge.upstream).push(edge.downstream);
    if (!upstreamOf.has(edge.downstream)) upstreamOf.set(edge.downstream, []);
    upstreamOf.get(edge.downstream).push(edge.upstream);
    uf.union(edge.upstream, edge.downstream);
    addEvidence(
      edge.downstream,
      `root-cause edge: ${edge.upstream} is the upstream cause of ${edge.downstream}`,
    );
  }

  function transitiveUpstream(fp) {
    const seen = new Set();
    const stack = [...(upstreamOf.get(fp) ?? [])];
    while (stack.length > 0) {
      const cur = stack.pop();
      if (seen.has(cur)) continue;
      seen.add(cur);
      stack.push(...(upstreamOf.get(cur) ?? []));
    }
    return seen;
  }

  // 3. Silences: direct silence windows per incident.
  const silenceWindows = new Map();
  for (const silence of input.silences ?? []) {
    const startMs = toMs(silence.startsAt);
    const endMs = toMs(silence.endsAt);
    for (const incident of incidents.values()) {
      if (!matchLabels(silence.matchers ?? {}, incident)) continue;
      if (!silenceWindows.has(incident.fingerprint)) {
        silenceWindows.set(incident.fingerprint, []);
      }
      silenceWindows.get(incident.fingerprint).push({
        silenceId: silence.id,
        startMs,
        endMs,
      });
      addEvidence(
        incident.fingerprint,
        `silence ${silence.id} matches directly for [${iso(startMs)}, ${iso(endMs)}]`,
      );
    }
  }

  // 4. Inhibition: a downstream incident is inhibited while any transitive
  //    upstream root cause is silenced. Only explicit root-cause edges create
  //    inhibition; independent faults are never inhibited.
  const suppressionChains = [];
  const inhibitedWindows = new Map();
  for (const incident of incidents.values()) {
    for (const upstream of transitiveUpstream(incident.fingerprint)) {
      for (const window of silenceWindows.get(upstream) ?? []) {
        if (
          !overlaps(
            incident.startsAtMs,
            incident.endsAtMs,
            window.startMs,
            window.endMs,
          )
        ) {
          continue;
        }
        if (!inhibitedWindows.has(incident.fingerprint)) {
          inhibitedWindows.set(incident.fingerprint, []);
        }
        inhibitedWindows.get(incident.fingerprint).push({
          startMs: window.startMs,
          endMs: window.endMs,
          upstream,
          silenceId: window.silenceId,
        });
        suppressionChains.push({
          suppressed: incident.fingerprint,
          upstream,
          silence: window.silenceId,
          window: { from: iso(window.startMs), to: iso(window.endMs) },
        });
        addEvidence(
          incident.fingerprint,
          `inhibited by silence ${window.silenceId} on upstream root cause ${upstream}`,
        );
      }
    }
  }

  // 5. Effective start: if inhibited/silenced at start, the notification clock
  //    begins when the covering window ends (silence lifted).
  function effectiveStart(incident) {
    let start = incident.startsAtMs;
    const windows = [
      ...(silenceWindows.get(incident.fingerprint) ?? []),
      ...(inhibitedWindows.get(incident.fingerprint) ?? []),
    ];
    let moved = true;
    while (moved) {
      moved = false;
      for (const window of windows) {
        if (window.startMs <= start && start < window.endMs) {
          start = window.endMs;
          moved = true;
        }
      }
    }
    return start;
  }

  // 6. Group incidents that share a root cause (union-find components).
  const components = new Map();
  for (const fp of incidents.keys()) {
    const root = uf.find(fp);
    if (!components.has(root)) components.set(root, []);
    components.get(root).push(fp);
  }

  const groups = [];
  const notificationPlan = [];

  for (const members of components.values()) {
    const memberIncidents = members.map((fp) => incidents.get(fp));
    const representative = [...memberIncidents].sort((a, b) => {
      const bySeverity = severityRank(b.severity) - severityRank(a.severity);
      if (bySeverity !== 0) return bySeverity;
      return a.startsAtMs - b.startsAtMs;
    })[0];

    const groupId = `group:${representative.fingerprint}`;
    const startsAtMs = Math.min(...memberIncidents.map((i) => i.startsAtMs));
    const anyOpen = memberIncidents.some((i) => i.endsAtMs === null);
    const endsAtMs = anyOpen
      ? null
      : Math.max(...memberIncidents.map((i) => i.endsAtMs));
    const notifyFromMs = Math.min(...memberIncidents.map((i) => effectiveStart(i)));

    if (members.length > 1) {
      for (const fp of members) {
        addEvidence(
          fp,
          `merged into ${groupId} via shared root cause; representative is ${representative.fingerprint} (severity=${representative.severity})`,
        );
      }
    }

    const matchingPolicies = (input.escalationPolicies ?? []).filter((p) =>
      policyMatches(p, representative),
    );
    if (matchingPolicies.length > 1) {
      conflicts.push({
        type: 'policy-overlap',
        group: groupId,
        policies: matchingPolicies.map((p) => p.id),
        detail: `multiple escalation policies match ${representative.fingerprint}; using ${matchingPolicies[0].id}`,
      });
    }
    const policy = matchingPolicies[0] ?? null;

    groups.push({
      id: groupId,
      members,
      representative: representative.fingerprint,
      severity: representative.severity,
      startsAt: iso(startsAtMs),
      endsAt: iso(endsAtMs),
      notifyFrom: iso(notifyFromMs),
      policy: policy?.id ?? null,
    });

    if (!policy) {
      addEvidence(
        representative.fingerprint,
        'no escalation policy matched; no notifications scheduled',
      );
      continue;
    }

    if (endsAtMs !== null && endsAtMs <= notifyFromMs) {
      addEvidence(
        representative.fingerprint,
        `incident resolved at ${iso(endsAtMs)} while still silenced/inhibited; closed without notification`,
      );
      continue;
    }

    for (const [index, level] of (policy.levels ?? []).entries()) {
      const notifyAtMs = notifyFromMs + level.afterMinutes * MINUTE;
      if (endsAtMs !== null && notifyAtMs > endsAtMs) {
        addEvidence(
          representative.fingerprint,
          `level ${index} at ${iso(notifyAtMs)} skipped: incident closed at ${iso(endsAtMs)}`,
        );
        continue;
      }
      const targets = [];
      for (const targetGroup of level.notify ?? []) {
        const user = resolveOncall(input.oncall ?? {}, targetGroup, notifyAtMs);
        if (user === null) {
          conflicts.push({
            type: 'no-oncall-coverage',
            group: groupId,
            oncallGroup: targetGroup,
            at: iso(notifyAtMs),
            detail: `no on-call user scheduled for ${targetGroup} at ${iso(notifyAtMs)}`,
          });
        }
        targets.push({ oncallGroup: targetGroup, user });
      }
      notificationPlan.push({
        type: 'notify',
        group: groupId,
        severity: representative.severity,
        level: index,
        at: iso(notifyAtMs),
        targets,
      });
    }

    if (endsAtMs !== null) {
      const targets = [];
      const lastLevel = (policy.levels ?? []).at(-1);
      for (const targetGroup of lastLevel?.notify ?? []) {
        targets.push({
          oncallGroup: targetGroup,
          user: resolveOncall(input.oncall ?? {}, targetGroup, endsAtMs),
        });
      }
      notificationPlan.push({
        type: 'close',
        group: groupId,
        severity: representative.severity,
        level: null,
        at: iso(endsAtMs),
        targets,
      });
    }
  }

  // 7. Escalation races: independent groups escalating to the same on-call
  //    group within the race window compete for the same responder.
  const notifySteps = notificationPlan.filter((step) => step.type === 'notify');
  for (let i = 0; i < notifySteps.length; i += 1) {
    for (let j = i + 1; j < notifySteps.length; j += 1) {
      const a = notifySteps[i];
      const b = notifySteps[j];
      if (a.group === b.group) continue;
      const shared = a.targets
        .map((t) => t.oncallGroup)
        .filter((g) => b.targets.some((t) => t.oncallGroup === g));
      if (shared.length === 0) continue;
      const gap = Math.abs(toMs(a.at) - toMs(b.at));
      if (gap <= raceWindowMs) {
        conflicts.push({
          type: 'escalation-race',
          oncallGroups: shared,
          groups: [a.group, b.group],
          at: [a.at, b.at],
          detail: `${a.group} and ${b.group} escalate to ${shared.join(', ')} within ${raceWindowMs / MINUTE} minutes`,
        });
      }
    }
  }

  notificationPlan.sort((a, b) => toMs(a.at) - toMs(b.at));

  return {
    generatedAt: iso(now),
    incidents: [...incidents.values()].map((incident) => ({
      fingerprint: incident.fingerprint,
      source: incident.source,
      severity: incident.severity,
      events: incident.events,
      startsAt: iso(incident.startsAtMs),
      endsAt: iso(incident.endsAtMs),
    })),
    duplicates,
    groups,
    notificationPlan,
    suppressionChains,
    conflicts,
    evidence: Object.fromEntries(evidence),
  };
}
