'use strict';

// What a new account starts with.
//
// A new intern should not begin with nothing and wait for someone to notice. Instead the
// account is provisioned from its own role: Red looks at the people who already hold it, sees
// how many files each has been given by name, and hands the newcomer the same number - taking
// the files the most role-mates already have, most-shared first.
//
// Two things bound it, so this can only ever match the role and never exceed it:
//   - clearance. A file above the role's clearance is never granted, whoever else has it.
//   - the peers themselves. With no peers there is no precedent, and nothing is granted.
//
// Role grants and project grants are not copied: those already apply to the whole role, so the
// newcomer has them the moment their role is set. Only grants made to individuals need
// repeating, and those are what this repeats.

// A quiet ceiling, so one over-shared peer can't hand a newcomer hundreds of files.
const MAX_GRANTS = 25;

// The average, rounded to nearest, of how many files each peer holds. Rounded rather than
// floored so a role where most people have one file still gives the newcomer one.
function peerAverage(counts) {
  if (!counts.length) return 0;
  return Math.round(counts.reduce((total, n) => total + n, 0) / counts.length);
}

// Decides the grants for a new account. `peers` is one entry per existing holder of the role,
// each listing the file ids granted to them by name; `candidates` is those files with the
// confidentiality the newcomer's clearance has to cover.
//
// Returns the file ids to grant, and the numbers behind the decision so the result can be
// explained rather than just applied.
function planFor({ peers, candidates, clearance, max = MAX_GRANTS }) {
  const counts = peers.map((peer) => peer.fileIds.length);
  const target = Math.min(peerAverage(counts), max);
  if (!target) return { target, granted: [], peers: peers.length, popularity: [] };

  // How many peers hold each file. A file two of three interns have is a better guess at "what
  // an intern needs" than one only a single person was given.
  const held = new Map();
  for (const peer of peers) {
    for (const id of new Set(peer.fileIds)) held.set(id, (held.get(id) ?? 0) + 1);
  }

  const reachable = candidates
    .filter((file) => file.confidentiality <= clearance && held.has(file.id))
    .map((file) => ({ id: file.id, peers: held.get(file.id), confidentiality: file.confidentiality }))
    // Most widely held first; then the least sensitive, so a tie never resolves towards the
    // more confidential file; then by id, so the result is stable.
    .sort((a, b) => b.peers - a.peers || a.confidentiality - b.confidentiality || a.id - b.id);

  return {
    target,
    peers: peers.length,
    granted: reachable.slice(0, target).map((file) => file.id),
    popularity: reachable,
  };
}

module.exports = { MAX_GRANTS, peerAverage, planFor };
