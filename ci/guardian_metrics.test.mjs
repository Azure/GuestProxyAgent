import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { reportMetrics, validateDocument } from './guardian_metrics.mjs';

function record(overrides = {}) {
  return {
    repository: 'example/repo', pr_number: 1, cohort: 'treatment', risk_tier: 'R2',
    eligibility: 'eligible', exclusion_reason: null, ai_assisted: true, language: 'rust',
    changed_lines: 120, changed_files: 3, merged_at: null,
    issue_to_pr_minutes: null, ready_to_first_review_minutes: null,
    ready_to_approval_minutes: null, pr_to_merge_minutes: null,
    active_review_minutes: null, rework_cycles: null,
    escaped_defects: null, rollback_or_hotfix: null,
    evidence_reference: 'synthetic fixture', findings: [], ...overrides,
  };
}

function document(records = []) {
  return { schema_version: 1, as_of: '2026-10-28T20:00:00Z', records };
}

test('empty population and missing data yield null estimates, not success-shaped zeroes', () => {
  const empty = reportMetrics(document());
  assert.equal(empty.population.supplied, 0);
  assert.deepEqual(empty.overall.findings.precision, { numerator: 0, denominator: 0, ratio: null });
  const result = reportMetrics(document([record()]));
  assert.deepEqual(result.overall.durations_minutes.active_review_minutes,
    { n: 0, missing: 1, p50: null, p90: null });
  assert.equal(result.interpretation.comparison_is_directional, true);
});

test('nearest-rank percentiles preserve exact measurements and per-field missing counts', () => {
  const records = Array.from({ length: 10 }, (_, index) =>
    record({ pr_number: index + 1, active_review_minutes: index + 1 }));
  records.push(record({ pr_number: 11 }));
  const metric = reportMetrics(document(records)).overall.durations_minutes.active_review_minutes;
  assert.deepEqual(metric, { n: 10, missing: 1, p50: 5, p90: 9 });
});

test('precision includes duplicates and not actionable as negatives, but excludes unresolved', () => {
  const dispositions = ['Accepted and fixed', 'Valid risk accepted', 'Deferred with linked work item',
    'False positive', 'Duplicate', 'Not actionable', null];
  const findings = dispositions.map((disposition, index) =>
    ({ id: `F${index}`, severity: index < 2 ? 'high' : 'medium', disposition }));
  const result = reportMetrics(document([record({ findings })])).overall.findings;
  assert.deepEqual(result.precision, { numerator: 3, denominator: 6, ratio: 0.5 });
  assert.deepEqual(result.high_severity_precision, { numerator: 2, denominator: 2, ratio: 1 });
  assert.deepEqual(result.false_positive_rate, { numerator: 1, denominator: 6, ratio: 1 / 6 });
  assert.equal(result.unresolved, 1);
});

test('30-day observation boundary and outcome denominators are exact', () => {
  const records = [
    record({ merged_at: '2026-09-28T20:00:00Z', escaped_defects: 2, rollback_or_hotfix: true }),
    record({ pr_number: 2, merged_at: '2026-09-28T19:59:59Z', escaped_defects: 0,
      rollback_or_hotfix: false }),
    record({ pr_number: 3, merged_at: '2026-09-28T20:00:01Z' }),
    record({ pr_number: 4, merged_at: '2026-09-27T20:00:00Z' }),
    record({ pr_number: 5 }),
  ];
  const result = reportMetrics(document(records)).overall.safety;
  assert.equal(result.mature_prs, 3);
  assert.equal(result.immature_prs, 1);
  assert.equal(result.unmerged_prs, 1);
  assert.equal(result.missing_defect_outcomes, 1);
  assert.equal(result.missing_rollback_outcomes, 1);
  assert.deepEqual(result.defects_per_observed_pr, { numerator: 2, denominator: 2, ratio: 1 });
  assert.deepEqual(result.affected_pr_rate, { numerator: 1, denominator: 2, ratio: 0.5 });
  assert.deepEqual(result.rollback_or_hotfix_rate, { numerator: 1, denominator: 2, ratio: 0.5 });
});

test('exclusions are counted with reasons and never included in outcome summaries', () => {
  const result = reportMetrics(document([
    record(), record({ pr_number: 2, eligibility: 'excluded', exclusion_reason: 'emergency',
      active_review_minutes: 900 }),
  ]));
  assert.equal(result.population.excluded, 1);
  assert.equal(result.population.exclusions[0].reason, 'emergency');
  assert.equal(result.overall.pr_count, 1);
  assert.equal(result.overall.durations_minutes.active_review_minutes.n, 0);
});

test('cohorts, risk, size, language, and authorship are separated', () => {
  const result = reportMetrics(document([
    record({ changed_lines: 100, changed_files: 5 }),
    record({ pr_number: 2, cohort: 'control', risk_tier: 'R3', changed_lines: 301,
      changed_files: 16, language: 'c', ai_assisted: false }),
    record({ pr_number: 3, changed_lines: 300, changed_files: 15 }),
    record({ pr_number: 4, changed_lines: 1000 }),
    record({ pr_number: 5, changed_lines: 1001 }),
  ]));
  assert.equal(result.cohorts.control.pr_count, 1);
  assert.equal(result.cohorts.treatment.pr_count, 4);
  assert.equal(result.strata.length, 5);
  assert.deepEqual(new Set(result.strata.map(group => group.dimensions.changed_line_band)),
    new Set(['0-100', '101-300', '301-1000', '1001+']));
  assert.deepEqual(new Set(result.strata.map(group => group.dimensions.file_count_band)),
    new Set(['0-5', '6-15', '16+']));
  assert.ok(result.strata.every(group => group.directional));
});

test('20 observations per arm removes only the small-arm flag, never the safety caveat', () => {
  const records = Array.from({ length: 40 }, (_, index) =>
    record({ pr_number: index + 1, cohort: index < 20 ? 'control' : 'treatment' }));
  const result = reportMetrics(document(records));
  assert.equal(result.interpretation.comparison_is_directional, false);
  assert.ok(result.interpretation.caveats.some(text => text.includes('Rare safety')));
  assert.ok(result.strata.every(group => !group.directional));
});

test('rejects invalid numbers, missing/unknown fields, enums, dates, duplicates, and false maturity', () => {
  const invalidRecords = [
    record({ active_review_minutes: -1 }), record({ active_review_minutes: NaN }),
    record({ active_review_minutes: Infinity }), record({ rework_cycles: 0.5 }),
    record({ changed_lines: '120' }), record({ changed_files: Number.MAX_SAFE_INTEGER + 1 }),
    record({ cohort: 'other' }), record({ risk_tier: 'HIGH' }),
    record({ ai_assisted: 'true' }), record({ exclusion_reason: 'hidden exclusion' }),
    record({ eligibility: 'excluded' }), record({ language: '' }),
    record({ evidence_reference: '' }), record({ extra: 1 }),
    record({ merged_at: '2026-02-30T00:00:00Z' }),
    record({ merged_at: '2026-10-29T20:00:00Z' }),
    record({ merged_at: '2026-09-01T00:00:00+00:00' }),
    record({ pr_to_merge_minutes: 1 }), record({ escaped_defects: 0 }),
    record({ merged_at: '2026-09-28T20:00:01Z', rollback_or_hotfix: false }),
    record({ findings: [{ id: 'F1', severity: 'high', disposition: 'fixed' }] }),
    record({ findings: [{ id: 'F1', severity: 'urgent', disposition: null }] }),
    record({ cohort: 'control', findings: [{ id: 'F1', severity: 'high', disposition: null }] }),
    record({ findings: Array(2).fill({ id: 'F1', severity: 'high', disposition: null }) }),
  ];
  const missing = record();
  delete missing.active_review_minutes;
  invalidRecords.push(missing);
  for (const invalid of invalidRecords) assert.throws(() => validateDocument(document([invalid])));
  assert.throws(() => validateDocument(document([record(), record({ repository: 'EXAMPLE/REPO' })])),
    /duplicate PR/);
  assert.throws(() => validateDocument({ ...document(), schema_version: 2 }), /schema_version/);
  assert.throws(() => validateDocument({ ...document(), as_of: 'invalid' }), /timestamp/);
  assert.throws(() => validateDocument({ ...document(), records: {} }), /array/);
});

test('ADV-FINAL-01: CLI rejects a trailing immature outcome atomically at millisecond precision', () => {
  const directory = mkdtempSync(join(tmpdir(), 'gpa-metrics-boundary-'));
  const script = fileURLToPath(new URL('./guardian_metrics.mjs', import.meta.url));
  const file = join(directory, 'records.json');
  try {
    const input = document([
      record(),
      record({ pr_number: 2, merged_at: '2026-09-28T20:00:00.001Z',
        escaped_defects: 0, rollback_or_hotfix: false }),
    ]);
    const original = JSON.stringify(input);
    writeFileSync(file, original);
    const premature = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
    assert.equal(premature.status, 1);
    assert.equal(premature.stdout, '');
    assert.match(premature.stderr, /records\[1\]: safety outcomes require a completed 30-day/);
    assert.equal(readFileSync(file, 'utf8'), original);

    input.as_of = '2026-10-28T20:00:00.001Z';
    const matureInput = JSON.stringify(input);
    writeFileSync(file, matureInput);
    const mature = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
    assert.equal(mature.status, 0, mature.stderr);
    const report = JSON.parse(mature.stdout);
    assert.equal(report.population.eligible, 2);
    assert.equal(report.overall.safety.mature_prs, 1);
    assert.equal(report.overall.safety.immature_prs, 0);
    assert.deepEqual(report.overall.safety.defects_per_observed_pr,
      { numerator: 0, denominator: 1, ratio: 0 });
    assert.deepEqual(report.overall.safety.rollback_or_hotfix_rate,
      { numerator: 0, denominator: 1, ratio: 0 });
    assert.equal(readFileSync(file, 'utf8'), matureInput);
  } finally {
    rmSync(file, { force: true });
    rmdirSync(directory);
  }
});

test('CLI reports valid JSON and explicit errors without altering input, including a UTF-8 BOM', () => {
  const directory = mkdtempSync(join(tmpdir(), 'gpa-metrics-'));
  const script = fileURLToPath(new URL('./guardian_metrics.mjs', import.meta.url));
  const file = join(directory, 'records.json');
  try {
    const original = `\uFEFF${JSON.stringify(document([record()]))}`;
    writeFileSync(file, original);
    const success = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
    assert.equal(success.status, 0, success.stderr);
    assert.equal(JSON.parse(success.stdout).population.eligible, 1);
    assert.equal(readFileSync(file, 'utf8'), original);
    writeFileSync(file, '{invalid');
    const invalid = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
    assert.equal(invalid.status, 1);
    assert.equal(invalid.stdout, '');
    assert.match(invalid.stderr, /guardian_metrics:/);
    const missing = spawnSync(process.execPath, [script, join(directory, 'missing.json')],
      { encoding: 'utf8' });
    assert.equal(missing.status, 1);
    assert.equal(missing.stdout, '');
    const usage = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    assert.equal(usage.status, 1);
    assert.match(usage.stderr, /Usage:/);
  } finally {
    rmSync(file, { force: true });
    rmdirSync(directory);
  }
});
