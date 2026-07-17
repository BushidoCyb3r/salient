const leadReasonLabels = {
  'policy-denied': 'policy denied',
  'contradicted': 'role contradicted',
  'undocumented': 'undocumented',
  'new-provider': 'new provider',
  'new-service': 'new service',
  'sole-provider': 'sole provider',
};

export function csvCell(value) {
  const text = (value || '').trim();
  return /[",\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

export function leadReasonLabel(reason) {
  return leadReasonLabels[reason] || reason;
}

export function leadDossierText(lead) {
  return lead.ip + (lead.hostname ? ' (' + lead.hostname + ')' : '') +
    '\nreason: ' + leadReasonLabel(lead.reason) +
    '\nservice: ' + lead.service + ' (port ' + lead.port + ')' +
    (lead.inventory_status ? '\ninventory: ' + lead.inventory_status : '') +
    (lead.rank ? '\nrank: #' + lead.rank : '') +
    '\nevidence: ' + lead.evidence +
    (lead.rule_evidence ? '\ndenied by: ' + lead.rule_evidence : '') +
    '\nclients: ' + lead.clients + (lead.sample_clients ? ' (' + lead.sample_clients.join(', ') + ')' : '') +
    (lead.subnets ? '\nsubnets: ' + lead.subnets.join(', ') : '') +
    (lead.sensors ? '\nsensors: ' + lead.sensors.join(', ') : '') +
    '\nalternate providers: ' + (lead.alternate_providers?.length ? lead.alternate_providers.join(', ') : 'no alternate provider observed') +
    '\nfirst seen: ' + lead.first_seen +
    '\nlast seen: ' + lead.last_seen;
}

export function topTerrainNodes(model, limit = 15) {
  return (model.nodes || [])
    .filter((node) => node.rank > 0 && (!node.agg_count || node.device))
    .sort((a, b) => a.rank - b.rank)
    .slice(0, limit);
}
