'use strict';

// Decoy projects (telemetry/honeytokens.js) in the routes that could touch one.
//
// A decoy sits in a risky account's project list. Opening one must look like opening an empty
// project. Changing one is the trip: it is recorded, every session the account has is revoked,
// and the request is refused as a signed-out one - which is what sends the browser back to the
// sign-in page. The identity throttle then turns it into a freeze, so signing back in waits for
// an admin.
//
// An id in the decoy range is not enough on its own: trip() returns null unless a live decoy with
// that id was planted for this very account. Otherwise anyone could sign themselves out by
// guessing a number, and the request falls through to the ordinary "not found" instead.

const { sessionEnded } = require('../http/errors');
const { isDecoyId } = require('../telemetry/honeytokens');

function createDecoyTrap({ stores, telemetry, protection }) {
  // Resolves when the id is not a live decoy for this account; throws when it was, and is now tripped.
  async function spring({ req, user, id, interaction = 'modified', client }) {
    if (!isDecoyId(id)) return;
    const report = await telemetry.honeytokens.trip({
      user, decoyId: id, interaction, client, tokenHash: req.sessionTokenHash,
    });
    if (!report) return;

    stores.sessions.removeAll(user.id);
    stores.audit.record('security.honeytoken_tripped', {
      actor: user, target: user, ...client, details: { interaction, decoy: report.decoy, score: report.score },
    });
    await protection?.onHoneytokenTrip(report);
    throw sessionEnded();
  }

  // Whether this id is a decoy planted for this account, for the reads that must look ordinary.
  const isPlanted = async (user, id) =>
    isDecoyId(id) && (await telemetry.honeytokens.listFor(user.id)).some((decoy) => decoy.id === id);

  return { spring, isPlanted, isDecoyId };
}

module.exports = { createDecoyTrap };
