export namespace graph {
	
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

}

export namespace main {
	
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

