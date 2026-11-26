#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const REPO_ROOT = process.cwd();
const RATCHET_FILE = path.join(REPO_ROOT, '.comment-ratchet.json');
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', '.git', '.agents']);
const CODE_EXT_REGEX = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;

function walkCodeFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkCodeFiles(full, out);
    } else if (CODE_EXT_REGEX.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function extractComments(filePath, text) {
  const sf = ts.createSourceFile(filePath, text, ts.ScriptTarget.Latest, true);
  const seen = new Map();

  function addRanges(ranges) {
    if (!ranges) return;
    for (const r of ranges) {
      if (seen.has(r.pos)) continue;
      const raw = text.slice(r.pos, r.end);
      if (r.pos === 0 && raw.startsWith('#!')) continue;
      const startLC = sf.getLineAndCharacterOfPosition(r.pos);
      const endLC = sf.getLineAndCharacterOfPosition(r.end);
      seen.set(r.pos, {
        pos: r.pos,
        end: r.end,
        startLine: startLC.line + 1,
        startCol: startLC.character + 1,
        endLine: endLC.line + 1,
        kind: r.kind === ts.SyntaxKind.SingleLineCommentTrivia ? 'line' : 'block',
        text: raw,
      });
    }
  }

  function visit(node) {
    addRanges(ts.getLeadingCommentRanges(text, node.pos));
    addRanges(ts.getTrailingCommentRanges(text, node.end));
    for (const child of node.getChildren(sf)) {
      visit(child);
    }
  }

  visit(sf);
  return [...seen.values()].sort((a, b) => a.pos - b.pos);
}

function loadRatchet() {
  if (!fs.existsSync(RATCHET_FILE)) {
    return { totalBudget: 0, files: {} };
  }
  const parsed = JSON.parse(fs.readFileSync(RATCHET_FILE, 'utf8'));
  return {
    totalBudget: typeof parsed.totalBudget === 'number' ? parsed.totalBudget : 0,
    files: parsed.files && typeof parsed.files === 'object' ? parsed.files : {},
  };
}

function writeRatchet(fileCounts) {
  const sortedFiles = {};
  let totalBudget = 0;
  for (const relPath of Object.keys(fileCounts).sort()) {
    const count = fileCounts[relPath];
    if (count > 0) {
      sortedFiles[relPath] = count;
      totalBudget += count;
    }
  }
  const payload = {
    totalBudget,
    files: sortedFiles,
  };
  fs.writeFileSync(RATCHET_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return payload;
}

function main() {
  const args = new Set(process.argv.slice(2));
  const updateRatchet = args.has('--update-ratchet');
  const reportMode = args.has('--report');
  const jsonMode = args.has('--json');

  const files = walkCodeFiles(REPO_ROOT).sort();
  const findings = [];
  const fileCounts = {};
  let totalComments = 0;
  let totalCommentLines = 0;

  for (const absPath of files) {
    const relPath = path.relative(REPO_ROOT, absPath).split(path.sep).join('/');
    const text = fs.readFileSync(absPath, 'utf8');
    const comments = extractComments(absPath, text);
    if (comments.length === 0) continue;

    fileCounts[relPath] = comments.length;
    totalComments += comments.length;

    const linesSet = new Set();
    for (const c of comments) {
      for (let l = c.startLine; l <= c.endLine; l++) linesSet.add(l);
      findings.push({ file: relPath, ...c });
    }
    totalCommentLines += linesSet.size;
  }

  if (jsonMode) {
    console.log(
      JSON.stringify(
        {
          totalComments,
          totalCommentLines,
          filesWithComments: Object.keys(fileCounts).length,
          fileCounts,
          findings,
        },
        null,
        2,
      ),
    );
    return;
  }

  if (reportMode) {
    if (findings.length === 0) {
      console.log('no-comments: 0 comments found across the codebase.');
      return;
    }
    console.log(
      `no-comments report: ${totalComments} comment(s) (${totalCommentLines} line(s)) across ${Object.keys(fileCounts).length} file(s):\n`,
    );
    for (const f of findings) {
      const firstLine = f.text.split('\n')[0].trim();
      console.log(`  ${f.file}:${f.startLine}:${f.startCol} (${f.kind}) ${firstLine}`);
    }
    return;
  }

  const ratchet = loadRatchet();

  if (updateRatchet) {
    const regressions = [];
    for (const [relPath, count] of Object.entries(fileCounts)) {
      const allowed = ratchet.files[relPath] ?? 0;
      if (count > allowed) {
        regressions.push({ relPath, count, allowed });
      }
    }
    if (regressions.length > 0 && !args.has('--force')) {
      console.error('no-comments: refusing to raise ratchet budget (use --force only when initializing a legacy baseline):');
      for (const r of regressions) {
        console.error(`  ${r.relPath}: ${r.count} comment(s) exceeds ratchet budget ${r.allowed}`);
      }
      process.exit(1);
    }
    const updated = writeRatchet(fileCounts);
    console.log(
      `no-comments: updated .comment-ratchet.json (totalBudget: ${updated.totalBudget}, files: ${Object.keys(updated.files).length}).`,
    );
    return;
  }

  const violations = [];
  const tightenOpportunities = [];

  const allTrackedPaths = new Set([...Object.keys(ratchet.files), ...Object.keys(fileCounts)]);
  for (const relPath of [...allTrackedPaths].sort()) {
    const actual = fileCounts[relPath] ?? 0;
    const allowed = ratchet.files[relPath] ?? 0;
    if (actual > allowed) {
      violations.push({ relPath, actual, allowed });
    } else if (actual < allowed) {
      tightenOpportunities.push({ relPath, actual, allowed });
    }
  }

  if (violations.length > 0) {
    console.error('no-comments lint failed: new or over-budget code comments detected.\n');
    for (const v of violations) {
      console.error(`  ${v.relPath}: found ${v.actual} comment(s), ratchet budget is ${v.allowed}`);
      const fileFindings = findings.filter((f) => f.file === v.relPath);
      for (const f of fileFindings) {
        const preview = f.text.split('\n')[0].trim().slice(0, 100);
        console.error(`    L${f.startLine}:${f.startCol}  ${preview}`);
      }
    }
    console.error('\nDelete the comment(s), move non-obvious decisions to docs/adr/, or file an issue for hacky code.');
    process.exit(1);
  }

  if (tightenOpportunities.length > 0) {
    console.error('no-comments ratchet can be tightened! Comment count decreased in:');
    for (const t of tightenOpportunities) {
      console.error(`  ${t.relPath}: ${t.allowed} -> ${t.actual}`);
    }
    console.error('\nRun `pnpm lint:ratchet` to lock in the lower budget.');
    process.exit(1);
  }

  console.log(
    `no-comments lint passed (${totalComments} comment(s) within ratchet budget ${ratchet.totalBudget}).`,
  );
}

main();
