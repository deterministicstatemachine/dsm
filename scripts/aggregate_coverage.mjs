#!/usr/bin/env node
// Aggregates coverage across layers: Rust (cargo-llvm-cov JSON), Android (JaCoCo HTML), Frontend (Jest lcov)
// Outputs: coverage/aggregate.json with raw metrics

import fs from 'fs/promises';
import path from 'path';

const root = process.cwd();

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

function pct(n, d) {
  if (!d || d === 0) return 0;
  return +(100 * (n / d)).toFixed(2);
}

function parseIntSafe(s) {
  if (s == null) return 0;
  return parseInt(String(s).replace(/[, %]/g, ''), 10) || 0;
}

async function parseRustCoverage() {
  const rustPath = path.join(root, 'coverage.json');
  if (!(await exists(rustPath))) return null;
  try {
    const text = await fs.readFile(rustPath, 'utf8');
    try {
      const j = JSON.parse(text);
      const totals = (j && (j.totals || (Array.isArray(j.data) && j.data[0] && j.data[0].totals))) || null;
      if (totals) {
        // Normalize shape
        return {
          lines: totals.lines || null,
          functions: totals.functions || null,
          regions: totals.regions || null,
        };
      }
    } catch (e) {
      // Fallback: regex extraction if JSON.parse fails (very large files sometimes)
      const linesM = text.match(/"lines"\s*:\s*\{[^}]*?"count"\s*:\s*(\d+),\s*"covered"\s*:\s*(\d+),[^}]*?"percent"\s*:\s*([\d.]+)/);
      const funcsM = text.match(/"functions"\s*:\s*\{[^}]*?"count"\s*:\s*(\d+),\s*"covered"\s*:\s*(\d+),[^}]*?"percent"\s*:\s*([\d.]+)/);
      const regsM = text.match(/"regions"\s*:\s*\{[^}]*?"count"\s*:\s*(\d+),\s*"covered"\s*:\s*(\d+),[^}]*?"percent"\s*:\s*([\d.]+)/);
      if (linesM) {
        return {
          lines: { count: +linesM[1], covered: +linesM[2], percent: +linesM[3] },
          functions: funcsM ? { count: +funcsM[1], covered: +funcsM[2], percent: +funcsM[3] } : null,
          regions: regsM ? { count: +regsM[1], covered: +regsM[2], percent: +regsM[3] } : null,
        };
      }
    }
  } catch (err) {
    console.error('Rust coverage parse error:', err.message);
  }
  return null;
}

async function parseFrontendLcov() {
  const lcovPath = path.join(root, 'dsm_client', 'frontend', 'coverage', 'lcov.info');
  if (!(await exists(lcovPath))) return null;
  const text = await fs.readFile(lcovPath, 'utf8');
  let linesFound = 0, linesHit = 0;
  let fnFound = 0, fnHit = 0;
  let brFound = 0, brHit = 0; // May be absent in Jest lcov
  const lines = text.split(/\n+/);
  for (const line of lines) {
    if (line.startsWith('DA:')) {
      // DA:<line number>,<execution count>[,<checksum>]
      const parts = line.slice(3).split(',');
      if (parts.length >= 2) {
        linesFound += 1;
        const hits = parseInt(parts[1], 10) || 0;
        if (hits > 0) linesHit += 1;
      }
    } else if (line.startsWith('FNF:')) {
      fnFound += parseInt(line.slice(4), 10) || 0;
    } else if (line.startsWith('FNH:')) {
      fnHit += parseInt(line.slice(4), 10) || 0;
    } else if (line.startsWith('BRF:')) {
      brFound += parseInt(line.slice(4), 10) || 0;
    } else if (line.startsWith('BRH:')) {
      brHit += parseInt(line.slice(4), 10) || 0;
    }
  }
  return {
    lines: { count: linesFound, covered: linesHit, percent: pct(linesHit, linesFound) },
    functions: { count: fnFound, covered: fnHit, percent: pct(fnHit, fnFound) },
    branches: brFound > 0 ? { count: brFound, covered: brHit, percent: pct(brHit, brFound) } : null,
  };
}

async function parseAndroidJaCoCo() {
  const htmlPath = path.join(root, 'dsm_client', 'android', 'app', 'build', 'reports', 'jacoco', 'jacocoTestReport', 'html', 'index.html');
  if (!(await exists(htmlPath))) return null;
  const html = await fs.readFile(htmlPath, 'utf8');
  const m = html.match(/<tfoot><tr>([\s\S]*?)<\/tr><\/tfoot>/);
  if (!m) return null;
  const row = m[1];
  const cells = Array.from(row.matchAll(/<td[^>]*>(.*?)<\/td>/g), (x) => x[1]);
  // Expect 13 cells: Total, Instr ("missed of total"), Instr %, Branches (missed of total), Branch %, Missed Cxty, Cxty, Missed Lines, Lines, Missed Methods, Methods, Missed Classes, Classes
  if (cells.length < 13) return null;
  const parseMissedOfTotal = (s) => {
    const parts = s.split('of').map((p) => parseIntSafe(p));
    return { missed: parts[0], total: parts[1] };
  };
  const instr = parseMissedOfTotal(cells[1]);
  const instrPct = parseIntSafe(cells[2]);
  const branch = parseMissedOfTotal(cells[3]);
  const branchPct = parseIntSafe(cells[4]);
  const cxtyMissed = parseIntSafe(cells[5]);
  const cxtyTotal = parseIntSafe(cells[6]);
  const linesMissed = parseIntSafe(cells[7]);
  const linesTotal = parseIntSafe(cells[8]);
  const methodsMissed = parseIntSafe(cells[9]);
  const methodsTotal = parseIntSafe(cells[10]);
  const classesMissed = parseIntSafe(cells[11]);
  const classesTotal = parseIntSafe(cells[12]);
  return {
    instructions: { count: instr.total, covered: instr.total - instr.missed, percent: instrPct },
    branches: { count: branch.total, covered: branch.total - branch.missed, percent: branchPct },
    complexity: { count: cxtyTotal, covered: cxtyTotal - cxtyMissed, percent: pct(cxtyTotal - cxtyMissed, cxtyTotal) },
    lines: { count: linesTotal, covered: linesTotal - linesMissed, percent: pct(linesTotal - linesMissed, linesTotal) },
    methods: { count: methodsTotal, covered: methodsTotal - methodsMissed, percent: pct(methodsTotal - methodsMissed, methodsTotal) },
    classes: { count: classesTotal, covered: classesTotal - classesMissed, percent: pct(classesTotal - classesMissed, classesTotal) },
  };
}

async function main() {
  const rust = await parseRustCoverage();
  const fe = await parseFrontendLcov();
  const android = await parseAndroidJaCoCo();

  const out = {
    generatedAt: 'deterministic',
    paths: {
      rust: 'coverage.json',
      frontend: 'dsm_client/frontend/coverage/lcov.info',
      android: 'dsm_client/android/app/build/reports/jacoco/jacocoTestReport/html/index.html',
    },
    rust,
    frontend: fe,
    android,
  };

  // Write machine-readable output
  const outDir = path.join(root, 'coverage');
  try { await fs.mkdir(outDir, { recursive: true }); } catch {}
  await fs.writeFile(path.join(outDir, 'aggregate.json'), JSON.stringify(out, null, 2));

  console.log('Wrote coverage/aggregate.json');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
