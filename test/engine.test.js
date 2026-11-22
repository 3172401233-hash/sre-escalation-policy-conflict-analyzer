import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/engine.js';

const ONCALL = {
  'sre-primary': {
    schedule: [
      { from: '2026-11-22T00:00:00Z', to: '2026-11-22T01:30:00Z', user: 'alice' },
      { from: '2026-11-22T01:30:00Z', to: '2026-11-23T00:00:00Z', user: 'bob' },
    ],
  },
  'sre-secondary': {
    schedule: [
      { from: '2026-11-22T00:00:00Z', to: '2026-11-23T00:00:00Z', user: 'carol' },
    ],
  },
};

const POLICY = {
  id: 'policy-critical',
  match: { severities: ['critical', 'major', 'warning'] },
  levels: [
    { afterMinutes: 0, notify: ['sre-primary'] },
    { afterMinutes: 15, notify: ['sre-primary', 'sre-secondary'] },
  ],
};

function event(overrides) {
  return {
    id: overrides.id,
    fingerprint: overrides.fingerprint,
    source: overrides.source ?? 'metric',
    severity: overrides.severity ?? 'critical',
    labels: overrides.labels ?? {},
    startsAt: overrides.startsAt ?? '2026-11-22T00:00:00Z',
    endsAt: overrides.endsAt ?? null,
  };
}

test('多源告警：metric/log/business 使用不同 severity，升级到同一值班组', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({ id: 'e1', fingerprint: 'fp-m', source: 'metric', severity: 'critical' }),
      event({ id: 'e2', fingerprint: 'fp-l', source: 'log', severity: 'major' }),
      event({ id: 'e3', fingerprint: 'fp-b', source: 'business', severity: 'warning' }),
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  assert.equal(plan.groups.length, 3);
  const notifies = plan.notificationPlan.filter((s) => s.type === 'notify' && s.level === 0);
  assert.equal(notifies.length, 3);
  for (const step of notifies) {
    assert.deepEqual(
      step.targets.map((t) => t.oncallGroup),
      ['sre-primary'],
    );
    assert.equal(step.targets[0].user, 'alice');
  }
  const severities = notifies.map((s) => s.severity).sort();
  assert.deepEqual(severities, ['critical', 'major', 'warning']);
});

test('静默解除：上游静默期间下游严重告警被抑制，静默结束后才通知', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({ id: 'up', fingerprint: 'fp-db', startsAt: '2026-11-22T00:00:00Z' }),
      event({ id: 'down', fingerprint: 'fp-api', startsAt: '2026-11-22T00:05:00Z' }),
    ],
    rootCauses: [{ upstream: 'fp-db', downstream: 'fp-api' }],
    silences: [
      {
        id: 'sil-1',
        matchers: { fingerprint: 'fp-db' },
        startsAt: '2026-11-21T23:00:00Z',
        endsAt: '2026-11-22T01:00:00Z',
      },
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  // 共享根因合并为一个组，下游被上游静默抑制。
  assert.equal(plan.groups.length, 1);
  assert.deepEqual(
    plan.suppressionChains.map((c) => [c.suppressed, c.upstream, c.silence]),
    [['fp-api', 'fp-db', 'sil-1']],
  );

  // 通知时钟从静默解除时间 01:00 开始。
  const group = plan.groups[0];
  assert.equal(group.notifyFrom, '2026-11-22T01:00:00.000Z');
  const first = plan.notificationPlan.find((s) => s.type === 'notify' && s.level === 0);
  assert.equal(first.at, '2026-11-22T01:00:00.000Z');
  assert.equal(first.targets[0].user, 'alice');
  const second = plan.notificationPlan.find((s) => s.type === 'notify' && s.level === 1);
  assert.equal(second.at, '2026-11-22T01:15:00.000Z');
  assert.equal(second.targets[0].user, 'alice');
});

test('独立故障：标签相似但无根因关系，不能被抑制或合并', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({
        id: 'a',
        fingerprint: 'fp-a',
        labels: { service: 'billing', host: 'api-1' },
      }),
      event({
        id: 'b',
        fingerprint: 'fp-b',
        startsAt: '2026-11-22T00:02:00Z',
        labels: { service: 'billing', host: 'api-1' },
      }),
    ],
    silences: [
      {
        id: 'sil-a',
        matchers: { fingerprint: 'fp-a' },
        startsAt: '2026-11-21T23:00:00Z',
        endsAt: '2026-11-22T01:00:00Z',
      },
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  // fp-a 被直接静默，fp-b 是独立故障：不合并、不抑制。
  assert.equal(plan.groups.length, 2);
  assert.equal(plan.suppressionChains.length, 0);
  const groupB = plan.groups.find((g) => g.representative === 'fp-b');
  assert.equal(groupB.notifyFrom, '2026-11-22T00:02:00.000Z');
  const notifyB = plan.notificationPlan.find(
    (s) => s.group === groupB.id && s.type === 'notify' && s.level === 0,
  );
  assert.equal(notifyB.at, '2026-11-22T00:02:00.000Z');
});

test('升级竞争：两个独立故障同时升级到同一值班组时报告冲突', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    raceWindowMinutes: 5,
    events: [
      event({ id: 'x', fingerprint: 'fp-x', startsAt: '2026-11-22T00:00:00Z' }),
      event({ id: 'y', fingerprint: 'fp-y', startsAt: '2026-11-22T00:03:00Z' }),
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  const races = plan.conflicts.filter((c) => c.type === 'escalation-race');
  assert.ok(races.length >= 1);
  assert.deepEqual(races[0].oncallGroups, ['sre-primary']);
  assert.deepEqual(races[0].groups.sort(), ['group:fp-x', 'group:fp-y']);
});

test('去重：相同 fingerprint 的重复事件合并，证据可追溯', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({ id: 'first', fingerprint: 'fp-dup' }),
      event({ id: 'second', fingerprint: 'fp-dup', startsAt: '2026-11-22T00:01:00Z' }),
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  assert.equal(plan.incidents.length, 1);
  assert.deepEqual(plan.duplicates, [{ event: 'second', mergedInto: 'fp-dup' }]);
  assert.ok(
    plan.evidence['fp-dup'].some((line) => line.includes('exact-fingerprint duplicate')),
  );
});

test('关闭：恢复后发送关闭通知，恢复后的升级层级被跳过', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({
        id: 'flap',
        fingerprint: 'fp-flap',
        startsAt: '2026-11-22T00:00:00Z',
        endsAt: '2026-11-22T00:10:00Z',
      }),
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  const steps = plan.notificationPlan;
  const level0 = steps.find((s) => s.type === 'notify' && s.level === 0);
  assert.equal(level0.at, '2026-11-22T00:00:00.000Z');
  assert.equal(steps.some((s) => s.type === 'notify' && s.level === 1), false);
  const close = steps.find((s) => s.type === 'close');
  assert.equal(close.at, '2026-11-22T00:10:00.000Z');
  assert.deepEqual(
    close.targets.map((t) => [t.oncallGroup, t.user]),
    [
      ['sre-primary', 'alice'],
      ['sre-secondary', 'carol'],
    ],
  );
  assert.ok(
    plan.evidence['fp-flap'].some((line) => line.includes('skipped')),
  );
});

test('值班表轮换：升级时间点落在哪个班次就通知谁', () => {
  const plan = analyze({
    now: '2026-11-22T02:00:00Z',
    events: [
      event({ id: 'late', fingerprint: 'fp-late', startsAt: '2026-11-22T01:20:00Z' }),
    ],
    escalationPolicies: [POLICY],
    oncall: ONCALL,
  });

  const level0 = plan.notificationPlan.find((s) => s.level === 0);
  const level1 = plan.notificationPlan.find((s) => s.level === 1);
  assert.equal(level0.targets[0].user, 'alice');
  assert.equal(level1.targets[0].user, 'bob');
});
