export {
  AggregateHosts,
  ApproveProvider,
  AssignIP,
  CancelScan,
  ClearDeclared,
  Connect,
  DeleteDevice,
  DeviceHints,
  DiscoverGrid,
  DismissHint,
  ExportImage,
  ExportMap,
  FlowEndpointIPs,
  Legend,
  ListDevices,
  ListSnapshots,
  LoadDeclared,
  LoadDriftModel,
  LoadFocusedModel,
  LoadHuntLeads,
  LoadModel,
  LoadReconcileModel,
  LoadReconcileModelCSV,
  LoadServiceAuthority,
  PickAssetCSV,
  PickDeviceConfigs,
  PinToMap,
  RemoveSegment,
  RunScan,
  SaveDevice,
  SetLabels,
  SetRole,
  SetSegment,
  SetShowAllPrivate,
  SuggestTags,
  SuggestTagsForHosts,
  UnapproveProvider,
  UnassignIP,
  UnpinFromMap,
} from '../wailsjs/go/main/App.js';

import { EventsOn as onRuntimeEvent } from '../wailsjs/runtime/runtime.js';

export function EventsOn(name, callback) {
  if (!globalThis.window?.runtime?.EventsOnMultiple) return () => {};
  return onRuntimeEvent(name, callback);
}
