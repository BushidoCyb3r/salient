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
	    roles?: RoleAssertion[];
	    subnet: string;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    sensors?: string[];
	    scores: ScoreSet;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostnames = source["hostnames"];
	        this.roles = this.convertValues(source["roles"], RoleAssertion);
	        this.subnet = source["subnet"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.sensors = source["sensors"];
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

