#!/usr/bin/env node
// Verify that each declared Fanwaave app is an actual gitlink to an approved
// repository. Does not fetch private submodules or require cross-org tokens.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const doc = readFileSync(".gitmodules", "utf8");
const entries = [];
let current;
for (const raw of doc.split(/\r?\n/)) {
  const line = raw.trim();
  const heading = line.match(/^\[submodule "([^"]+)"\]$/);
  if (heading) {
    current = { name: heading[1] };
    entries.push(current);
    continue;
  }
  const property = line.match(/^(path|url)\s*=\s*(\S+)$/);
  if (property) {
    assert.ok(current, "submodule property before section");
    assert.equal(current[property[1]], undefined, "duplicate submodule property");
    current[property[1]] = property[2];
  } else {
    assert.ok(!line || line.startsWith("#"), "unsupported .gitmodules directive");
  }
}
assert.ok(entries.length >= 12, "expected the Fanwaave application catalog");
const paths = new Set();
const names = new Set();
for (const entry of entries) {
  assert.equal(entry.name, entry.path, "submodule section name must equal its path");
  assert.match(entry.path, /^apps\/fanwaave-[a-z0-9.-]+$/, "invalid app path");
  const slug = entry.path.slice("apps/".length);
  assert.equal(entry.url, `https://github.com/fanwaave/${slug}.git`, "unapproved submodule origin");
  assert.ok(!paths.has(entry.path), "duplicate submodule path");
  assert.ok(!names.has(slug), "duplicate app slug");
  paths.add(entry.path);
  names.add(slug);
}
const index = execFileSync("git", ["ls-files", "--stage", "-z"], { encoding: "utf8" });
const gitlinks = new Set(
  index.split("\0").filter(Boolean).filter((row) => row.startsWith("160000 "))
    .map((row) => row.split("\t")[1]),
);
for (const path of paths) {
  assert.ok(gitlinks.has(path), `missing gitlink in index: ${path}`);
}
for (const path of gitlinks) {
  assert.ok(paths.has(path), `unlisted gitlink: ${path}`);
}
console.log(`Validated ${paths.size} Fanwaave pinned submodule gitlinks`);
