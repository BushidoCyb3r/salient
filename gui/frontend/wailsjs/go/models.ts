export namespace assist {
	
	export class DeviceTag {
	    node_id: string;
	    tags: string[];
	    confidence: number;
	    rationale: string;
	
	    static createFrom(source: any = {}) {
	        return new DeviceTag(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.node_id = source["node_id"];
	        this.tags = source["tags"];
	        this.confidence = source["confidence"];
	        this.rationale = source["rationale"];
	    }
	}
	export class TagResult {
	    tags: DeviceTag[];
	
	    static createFrom(source: any = {}) {
	        return new TagResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tags = this.convertValues(source["tags"], DeviceTag);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace devices {
	
	export class Device {
	    name: string;
	    type?: string;
	    notes?: string;
	    ips: string[];
	    owns_cidrs?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.notes = source["notes"];
	        this.ips = source["ips"];
	        this.owns_cidrs = source["owns_cidrs"];
	    }
	}
	export class Segment {
	    cidr: string;
	    name?: string;
	
	    static createFrom(source: any = {}) {
	        return new Segment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cidr = source["cidr"];
	        this.name = source["name"];
	    }
	}
	export class Registry {
	    devices: Device[];
	    labels?: Record<string, Array<string>>;
	    role_overrides?: Record<string, string>;
	    dismissed_hints?: string[];
	    pinned_ips?: string[];
	    show_all_private?: boolean;
	    segments?: Segment[];
	    approved_providers?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Registry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.devices = this.convertValues(source["devices"], Device);
	        this.labels = source["labels"];
	        this.role_overrides = source["role_overrides"];
	        this.dismissed_hints = source["dismissed_hints"];
	        this.pinned_ips = source["pinned_ips"];
	        this.show_all_private = source["show_all_private"];
	        this.segments = this.convertValues(source["segments"], Segment);
	        this.approved_providers = source["approved_providers"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace escli {
	
	export class ClusterInfo {
	    cluster_name: string;
	    // Go type: struct { Number string "json:\"number\"" }
	    version: any;
	
	    static createFrom(source: any = {}) {
	        return new ClusterInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cluster_name = source["cluster_name"];
	        this.version = this.convertValues(source["version"], Object);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace graph {
	
	export class TemporalProfile {
	    hour_histogram: number[];
	    dow_histogram: number[];
	    class: string;
	
	    static createFrom(source: any = {}) {
	        return new TemporalProfile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hour_histogram = source["hour_histogram"];
	        this.dow_histogram = source["dow_histogram"];
	        this.class = source["class"];
	    }
	}
	export class Edge {
	    src: string;
	    dst: string;
	    port: number;
	    service: string;
	    evidence?: string;
	    conn_count: number;
	    bytes_out: number;
	    bytes_in: number;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    sensors?: string[];
	    temporal?: TemporalProfile;
	
	    static createFrom(source: any = {}) {
	        return new Edge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.port = source["port"];
	        this.service = source["service"];
	        this.evidence = source["evidence"];
	        this.conn_count = source["conn_count"];
	        this.bytes_out = source["bytes_out"];
	        this.bytes_in = source["bytes_in"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.sensors = source["sensors"];
	        this.temporal = this.convertValues(source["temporal"], TemporalProfile);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class L2Gateway {
	    mac: string;
	    sensor?: string;
	    ip_count: number;
	
	    static createFrom(source: any = {}) {
	        return new L2Gateway(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mac = source["mac"];
	        this.sensor = source["sensor"];
	        this.ip_count = source["ip_count"];
	    }
	}
	export class ScoreSet {
	    dependency_in_degree: number;
	    pagerank: number;
	    betweenness: number;
	    composite: number;
	    rank: number;
	
	    static createFrom(source: any = {}) {
	        return new ScoreSet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dependency_in_degree = source["dependency_in_degree"];
	        this.pagerank = source["pagerank"];
	        this.betweenness = source["betweenness"];
	        this.composite = source["composite"];
	        this.rank = source["rank"];
	    }
	}
	export class RoleAssertion {
	    role: string;
	    confidence: number;
	    evidence: string[];
	
	    static createFrom(source: any = {}) {
	        return new RoleAssertion(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.role = source["role"];
	        this.confidence = source["confidence"];
	        this.evidence = source["evidence"];
	    }
	}
	export class Node {
	    ip: string;
	    hostnames?: string[];
	    tls_fingerprints?: string[];
	    ssh_host_keys?: string[];
	    roles?: RoleAssertion[];
	    terrain_evidence?: string[];
	    subnet: string;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    sensors?: string[];
	    mac?: string;
	    scores: ScoreSet;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostnames = source["hostnames"];
	        this.tls_fingerprints = source["tls_fingerprints"];
	        this.ssh_host_keys = source["ssh_host_keys"];
	        this.roles = this.convertValues(source["roles"], RoleAssertion);
	        this.terrain_evidence = source["terrain_evidence"];
	        this.subnet = source["subnet"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.sensors = source["sensors"];
	        this.mac = source["mac"];
	        this.scores = this.convertValues(source["scores"], ScoreSet);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class SnapshotMeta {
	    // Go type: time
	    created_at: any;
	    window: string;
	    scope: string[];
	    cluster_name: string;
	    sensors?: string[];
	    zero_coverage_cidrs?: string[];
	    l2_gateways?: L2Gateway[];
	    betweenness_sampled: boolean;
	    tool: string;
	
	    static createFrom(source: any = {}) {
	        return new SnapshotMeta(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.window = source["window"];
	        this.scope = source["scope"];
	        this.cluster_name = source["cluster_name"];
	        this.sensors = source["sensors"];
	        this.zero_coverage_cidrs = source["zero_coverage_cidrs"];
	        this.l2_gateways = this.convertValues(source["l2_gateways"], L2Gateway);
	        this.betweenness_sampled = source["betweenness_sampled"];
	        this.tool = source["tool"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Snapshot {
	    meta: SnapshotMeta;
	    nodes: Node[];
	    edges: Edge[];
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.meta = this.convertValues(source["meta"], SnapshotMeta);
	        this.nodes = this.convertValues(source["nodes"], Node);
	        this.edges = this.convertValues(source["edges"], Edge);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace hunt {
	
	export class Lead {
	    reason: string;
	    ip: string;
	    hostname?: string;
	    service: string;
	    port: number;
	    evidence: string;
	    clients: number;
	    sample_clients?: string[];
	    subnets?: string[];
	    sensors?: string[];
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    rank?: number;
	    inventory_status?: string;
	    alternate_providers?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Lead(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.reason = source["reason"];
	        this.ip = source["ip"];
	        this.hostname = source["hostname"];
	        this.service = source["service"];
	        this.port = source["port"];
	        this.evidence = source["evidence"];
	        this.clients = source["clients"];
	        this.sample_clients = source["sample_clients"];
	        this.subnets = source["subnets"];
	        this.sensors = source["sensors"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.rank = source["rank"];
	        this.inventory_status = source["inventory_status"];
	        this.alternate_providers = source["alternate_providers"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class ConnectRequest {
	    ESURL: string;
	    APIKey: string;
	    CACertPath: string;
	    FieldmapPath: string;
	    InsecureSkipVerify: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ConnectRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ESURL = source["ESURL"];
	        this.APIKey = source["APIKey"];
	        this.CACertPath = source["CACertPath"];
	        this.FieldmapPath = source["FieldmapPath"];
	        this.InsecureSkipVerify = source["InsecureSkipVerify"];
	    }
	}
	export class Hint {
	    key: string;
	    hostname: string;
	    ips: string[];
	
	    static createFrom(source: any = {}) {
	        return new Hint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.hostname = source["hostname"];
	        this.ips = source["ips"];
	    }
	}
	export class LegendItem {
	    Label: string;
	    Color: string;
	
	    static createFrom(source: any = {}) {
	        return new LegendItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Label = source["Label"];
	        this.Color = source["Color"];
	    }
	}
	export class ScanRequest {
	    Window: string;
	    Scope: string[];
	    MaxEdges: number;
	    TZ: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Window = source["Window"];
	        this.Scope = source["Scope"];
	        this.MaxEdges = source["MaxEdges"];
	        this.TZ = source["TZ"];
	    }
	}
	export class TagRequest {
	    SnapshotPath: string;
	    Provider: string;
	    Endpoint: string;
	    Model: string;
	    APIKey: string;
	    AllowRemote: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TagRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.SnapshotPath = source["SnapshotPath"];
	        this.Provider = source["Provider"];
	        this.Endpoint = source["Endpoint"];
	        this.Model = source["Model"];
	        this.APIKey = source["APIKey"];
	        this.AllowRemote = source["AllowRemote"];
	    }
	}

}

export namespace mapview {
	
	export class Group {
	    id: string;
	    cidr: string;
	    label: string;
	    sensors?: string[];
	    blind_spot: boolean;
	    sparse: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Group(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.cidr = source["cidr"];
	        this.label = source["label"];
	        this.sensors = source["sensors"];
	        this.blind_spot = source["blind_spot"];
	        this.sparse = source["sparse"];
	    }
	}
	export class MapEdge {
	    src: string;
	    dst: string;
	    class: string;
	    color: string;
	    label: string;
	    hosts: number;
	    conns: number;
	    width: number;
	    drift?: string;
	
	    static createFrom(source: any = {}) {
	        return new MapEdge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.class = source["class"];
	        this.color = source["color"];
	        this.label = source["label"];
	        this.hosts = source["hosts"];
	        this.conns = source["conns"];
	        this.width = source["width"];
	        this.drift = source["drift"];
	    }
	}
	export class MapNode {
	    id: string;
	    group: string;
	    label: string;
	    role: string;
	    tier: string;
	    composite: number;
	    rank?: number;
	    gateway: boolean;
	    inferred: boolean;
	    agg_count?: number;
	    evidence?: string[];
	    drift?: string;
	    device?: string;
	    device_type?: string;
	    labels?: string[];
	    role_override?: string;
	    services?: string[];
	    mac?: string;
	    vendor?: string;
	    pinned?: boolean;
	    suggested_tags?: string[];
	    suggestion_confidence?: number;
	    suggestion_rationale?: string;
	    suggestion_model?: string;
	
	    static createFrom(source: any = {}) {
	        return new MapNode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.group = source["group"];
	        this.label = source["label"];
	        this.role = source["role"];
	        this.tier = source["tier"];
	        this.composite = source["composite"];
	        this.rank = source["rank"];
	        this.gateway = source["gateway"];
	        this.inferred = source["inferred"];
	        this.agg_count = source["agg_count"];
	        this.evidence = source["evidence"];
	        this.drift = source["drift"];
	        this.device = source["device"];
	        this.device_type = source["device_type"];
	        this.labels = source["labels"];
	        this.role_override = source["role_override"];
	        this.services = source["services"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.pinned = source["pinned"];
	        this.suggested_tags = source["suggested_tags"];
	        this.suggestion_confidence = source["suggestion_confidence"];
	        this.suggestion_rationale = source["suggestion_rationale"];
	        this.suggestion_model = source["suggestion_model"];
	    }
	}
	export class Model {
	    groups: Group[];
	    nodes: MapNode[];
	    edges: MapEdge[];
	    findings: string[];
	    meta: graph.SnapshotMeta;
	    overview?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Model(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.groups = this.convertValues(source["groups"], Group);
	        this.nodes = this.convertValues(source["nodes"], MapNode);
	        this.edges = this.convertValues(source["edges"], MapEdge);
	        this.findings = source["findings"];
	        this.meta = this.convertValues(source["meta"], graph.SnapshotMeta);
	        this.overview = source["overview"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServiceProvider {
	    ip: string;
	    hostname?: string;
	    role: string;
	    service: string;
	    port: number;
	    evidence: string;
	    clients: number;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    rank?: number;
	
	    static createFrom(source: any = {}) {
	        return new ServiceProvider(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostname = source["hostname"];
	        this.role = source["role"];
	        this.service = source["service"];
	        this.port = source["port"];
	        this.evidence = source["evidence"];
	        this.clients = source["clients"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.rank = source["rank"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace scan {
	
	export class Result {
	    SnapshotPath: string;
	    ReportPath: string;
	    MapPath: string;
	    Snapshot: graph.Snapshot;
	    Truncated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.SnapshotPath = source["SnapshotPath"];
	        this.ReportPath = source["ReportPath"];
	        this.MapPath = source["MapPath"];
	        this.Snapshot = this.convertValues(source["Snapshot"], graph.Snapshot);
	        this.Truncated = source["Truncated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace snapshot {
	
	export class ArtifactEntry {
	    Timestamp: string;
	    Report: string;
	    Map: string;
	    Snapshot: string;
	
	    static createFrom(source: any = {}) {
	        return new ArtifactEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Timestamp = source["Timestamp"];
	        this.Report = source["Report"];
	        this.Map = source["Map"];
	        this.Snapshot = source["Snapshot"];
	    }
	}

}

