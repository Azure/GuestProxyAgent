import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const durationFields = [
  'issue_to_pr_minutes',
  'ready_to_first_review_minutes',
  'ready_to_approval_minutes',
  'pr_to_merge_minutes',
  'active_review_minutes',
];
const validDispositions = [
  'Accepted and fixed',
  'Valid risk accepted',
  'Deferred with linked work item',
  'False positive',
  'Duplicate',
  'Not actionable',
];
const acceptedDispositions = new Set(validDispositions.slice(0, 3));
const recordFields = [
  'repository', 'pr_number', 'cohort', 'risk_tier', 'eligibility',
  'exclusion_reason', 'ai_assisted', 'language', 'changed_lines', 'changed_files',
  'merged_at', ...durationFields, 'rework_cycles', 'escaped_defects',
  'rollback_or_hotfix', 'evidence_reference', 'findings',
];
const observationWindow = 30 * 24 * 60 * 60 * 1000;

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function fields(value, expected, location) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${location}: expected object`);
  const actual = Object.keys(value);
  requireCondition(actual.length === expected.length
    && expected.every(key => Object.hasOwn(value, key)),
  `${location}: fields must be exactly ${expected.join(', ')}`);
}

function nonempty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function nonnegative(value, integer = false) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    && (!integer || Number.isSafeInteger(value));
}

function timestamp(value, location) {
  requireCondition(typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value),
  `${location}: expected UTC ISO timestamp`);
  const time = Date.parse(value);
  const normalized = value.includes('.') ? value : value.replace('Z', '.000Z');
  requireCondition(Number.isFinite(time) && new Date(time).toISOString() === normalized,
    `${location}: invalid calendar timestamp`);
  return time;
}

export function validateDocument(document) {
  fields(document, ['schema_version', 'as_of', 'records'], 'document');
  requireCondition(document.schema_version === 1, 'document: unsupported schema_version');
  const asOf = timestamp(document.as_of, 'as_of');
  requireCondition(Array.isArray(document.records), 'records: expected array');
  const seen = new Set();
  for (const [index, record] of document.records.entries()) {
    const location = `records[${index}]`;
    fields(record, recordFields, location);
    requireCondition(typeof record.repository === 'string'
      && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(record.repository),
    `${location}: invalid repository`);
    requireCondition(Number.isSafeInteger(record.pr_number) && record.pr_number > 0,
      `${location}: invalid pr_number`);
    const identity = `${record.repository.toLowerCase()}#${record.pr_number}`;
    requireCondition(!seen.has(identity), `${location}: duplicate PR ${identity}`);
    seen.add(identity);
    requireCondition(['control', 'treatment'].includes(record.cohort),
      `${location}: invalid cohort`);
    requireCondition(['R0', 'R1', 'R2', 'R3'].includes(record.risk_tier),
      `${location}: invalid risk_tier`);
    requireCondition(['eligible', 'excluded'].includes(record.eligibility),
      `${location}: invalid eligibility`);
    requireCondition(record.eligibility === 'excluded'
      ? nonempty(record.exclusion_reason) : record.exclusion_reason === null,
    `${location}: exclusion_reason must explain exclusion or be null for eligible PRs`);
    requireCondition(typeof record.ai_assisted === 'boolean', `${location}: invalid ai_assisted`);
    requireCondition(nonempty(record.language) && nonempty(record.evidence_reference),
      `${location}: language and evidence_reference are required`);
    for (const field of ['changed_lines', 'changed_files']) {
      requireCondition(nonnegative(record[field], true), `${location}: invalid ${field}`);
    }
    for (const field of durationFields) {
      requireCondition(record[field] === null || nonnegative(record[field]),
        `${location}: invalid ${field}`);
    }
    for (const field of ['rework_cycles', 'escaped_defects']) {
      requireCondition(record[field] === null || nonnegative(record[field], true),
        `${location}: invalid ${field}`);
    }
    requireCondition(record.rollback_or_hotfix === null
      || typeof record.rollback_or_hotfix === 'boolean',
    `${location}: invalid rollback_or_hotfix`);
    const merged = record.merged_at === null ? null
      : timestamp(record.merged_at, `${location}.merged_at`);
    requireCondition(merged === null || merged <= asOf, `${location}: merge is after as_of`);
    requireCondition(merged !== null || record.pr_to_merge_minutes === null,
      `${location}: unmerged PR has merge duration`);
    const mature = merged !== null && asOf - merged >= observationWindow;
    requireCondition(mature
      || (record.escaped_defects === null && record.rollback_or_hotfix === null),
    `${location}: safety outcomes require a completed 30-day observation window`);
    requireCondition(Array.isArray(record.findings), `${location}: findings must be an array`);
    requireCondition(record.cohort !== 'control' || record.findings.length === 0,
      `${location}: control PR cannot have Guardian findings`);
    const findingIds = new Set();
    for (const finding of record.findings) {
      fields(finding, ['id', 'severity', 'disposition'], `${location}.finding`);
      requireCondition(nonempty(finding.id) && !findingIds.has(finding.id),
        `${location}: missing or duplicate finding id`);
      findingIds.add(finding.id);
      requireCondition(['critical', 'high', 'medium', 'low'].includes(finding.severity),
        `${location}: invalid finding severity`);
      requireCondition(finding.disposition === null || validDispositions.includes(finding.disposition),
        `${location}: invalid finding disposition`);
    }
  }
  return document;
}

function distribution(values) {
  const present = values.filter(value => value !== null).sort((a, b) => a - b);
  const percentile = fraction => present.length
    ? present[Math.ceil(fraction * present.length) - 1] : null;
  return { n: present.length, missing: values.length - present.length,
    p50: percentile(0.5), p90: percentile(0.9) };
}

function rate(numerator, denominator) {
  return { numerator, denominator, ratio: denominator ? numerator / denominator : null };
}

function sum(values) {
  return values.reduce((total, value) => total + value, 0);
}

function summarize(records, asOf) {
  const merged = records.filter(record => record.merged_at !== null);
  const mature = merged.filter(record => asOf - Date.parse(record.merged_at) >= observationWindow);
  const observedDefects = mature.filter(record => record.escaped_defects !== null);
  const observedRollback = mature.filter(record => record.rollback_or_hotfix !== null);
  const findings = records.flatMap(record => record.findings);
  const dispositioned = findings.filter(finding => finding.disposition !== null);
  const high = dispositioned.filter(finding => ['critical', 'high'].includes(finding.severity));
  const precision = list => rate(
    list.filter(finding => acceptedDispositions.has(finding.disposition)).length, list.length);
  return {
    pr_count: records.length,
    durations_minutes: Object.fromEntries(durationFields.map(field =>
      [field, distribution(records.map(record => record[field]))])),
    changed_lines: distribution(records.map(record => record.changed_lines)),
    changed_files: distribution(records.map(record => record.changed_files)),
    rework_cycles: distribution(records.map(record => record.rework_cycles)),
    active_review_minutes_per_merged_pr: distribution(merged.map(record => record.active_review_minutes)),
    safety: {
      merged_prs: merged.length,
      unmerged_prs: records.length - merged.length,
      mature_prs: mature.length,
      immature_prs: merged.length - mature.length,
      missing_defect_outcomes: mature.length - observedDefects.length,
      missing_rollback_outcomes: mature.length - observedRollback.length,
      defects_per_observed_pr: rate(sum(observedDefects.map(record => record.escaped_defects)),
        observedDefects.length),
      affected_pr_rate: rate(observedDefects.filter(record => record.escaped_defects > 0).length,
        observedDefects.length),
      rollback_or_hotfix_rate: rate(observedRollback.filter(record => record.rollback_or_hotfix).length,
        observedRollback.length),
    },
    findings: {
      total: findings.length,
      unresolved: findings.length - dispositioned.length,
      precision: precision(dispositioned),
      high_severity_precision: precision(high),
      false_positive_rate: rate(dispositioned.filter(finding =>
        finding.disposition === 'False positive').length, dispositioned.length),
    },
  };
}

function dimensions(record) {
  return {
    cohort: record.cohort,
    risk_tier: record.risk_tier,
    changed_line_band: record.changed_lines <= 100 ? '0-100'
      : record.changed_lines <= 300 ? '101-300'
        : record.changed_lines <= 1000 ? '301-1000' : '1001+',
    file_count_band: record.changed_files <= 5 ? '0-5'
      : record.changed_files <= 15 ? '6-15' : '16+',
    language: record.language,
    ai_assisted: record.ai_assisted,
  };
}

export function reportMetrics(input) {
  const document = validateDocument(input);
  const asOf = Date.parse(document.as_of);
  const eligible = document.records.filter(record => record.eligibility === 'eligible');
  const excluded = document.records.filter(record => record.eligibility === 'excluded');
  const groups = new Map();
  for (const record of eligible) {
    const dimension = dimensions(record);
    const key = JSON.stringify(dimension);
    if (!groups.has(key)) groups.set(key, { dimensions: dimension, records: [] });
    groups.get(key).records.push(record);
  }
  const cohorts = Object.fromEntries(['control', 'treatment'].map(cohort =>
    [cohort, summarize(eligible.filter(record => record.cohort === cohort), asOf)]));
  return {
    schema_version: 1,
    as_of: document.as_of,
    population: {
      supplied: document.records.length,
      eligible: eligible.length,
      excluded: excluded.length,
      exclusions: excluded.map(record => ({
        repository: record.repository, pr_number: record.pr_number, reason: record.exclusion_reason,
      })),
    },
    interpretation: {
      comparison_is_directional: Object.values(cohorts).some(cohort => cohort.pr_count < 20),
      caveats: [
        'Raw descriptive summaries only; no causal productivity or safety claim.',
        'Fewer than 20 eligible PRs per arm or 10 per stratum is directional.',
        'Missing values are excluded per metric and never imputed as zero.',
        'Rare safety events require adjudication and complete post-merge observation.',
      ],
    },
    overall: summarize(eligible, asOf),
    cohorts,
    strata: [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))
      .map(([, group]) => ({
        dimensions: group.dimensions,
        directional: group.records.length < 10,
        ...summarize(group.records, asOf),
      })),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    requireCondition(process.argv.length === 3,
      'Usage: node ci\\guardian_metrics.mjs <records.json>');
    const input = JSON.parse(readFileSync(process.argv[2], 'utf8').replace(/^\uFEFF/, ''));
    process.stdout.write(`${JSON.stringify(reportMetrics(input), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`guardian_metrics: ${error.message}\n`);
    process.exitCode = 1;
  }
}
