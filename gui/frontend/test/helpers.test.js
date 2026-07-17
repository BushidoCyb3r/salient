import assert from 'node:assert/strict';
import test from 'node:test';

import { csvCell, leadDossierText, topTerrainNodes } from '../src/helpers.js';

test('csvCell produces RFC 4180 cells', () => {
  assert.equal(csvCell(' plain '), 'plain');
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hello"'), '"say ""hello"""');
});

test('leadDossierText includes policy rule evidence', () => {
  const text = leadDossierText({
    ip: '10.0.0.8', hostname: 'db', reason: 'policy-denied', service: 'postgres', port: 5432,
    inventory_status: 'documented', rank: 2, evidence: 'responder-confirmed', rule_evidence: 'deny tcp any host 10.0.0.8 eq 5432',
    clients: 3, sample_clients: ['10.0.0.2'], subnets: ['10.0.0.0/24'], sensors: ['sensor-a'],
    alternate_providers: [], first_seen: '2026-07-17T10:00:00Z', last_seen: '2026-07-17T10:05:00Z',
  });

  assert.match(text, /reason: policy denied/);
  assert.match(text, /denied by: deny tcp any host 10\.0\.0\.8 eq 5432/);
  assert.match(text, /alternate providers: no alternate provider observed/);
});

test('topTerrainNodes ranks visible terrain and keeps named aggregates', () => {
  const nodes = topTerrainNodes({ nodes: [
    { id: 'hidden-aggregate', rank: 1, agg_count: 10 },
    { id: 'second', rank: 2 },
    { id: 'named-aggregate', rank: 1, agg_count: 10, device: 'edge-fw' },
    { id: 'unranked', rank: 0 },
  ] });

  assert.deepEqual(nodes.map((node) => node.id), ['named-aggregate', 'second']);
});
