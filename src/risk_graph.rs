//! In-memory directed risk graph of process events.

use crate::telemetry::ProcessEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Edge type between process event nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Spawn,
    Network,
    FileTouch,
}

/// A node in the risk graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub pid: u32,
    pub exe: String,
    pub verdict: String,
    pub timestamp: u64,
}

/// Directed edge with kind and weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from_pid: u32,
    pub to_pid: u32,
    pub kind: EdgeKind,
    pub weight: f32,
}

/// Thread-safe in-memory risk graph.
pub struct RiskGraph {
    nodes: HashMap<u32, GraphNode>,
    edges: Vec<GraphEdge>,
    parent_of: HashMap<u32, u32>,
}

/// Max nodes retained; oldest by timestamp evicted under pressure.
#[cfg(test)]
const MAX_GRAPH_NODES: usize = 64;
#[cfg(not(test))]
const MAX_GRAPH_NODES: usize = 4096;

impl Default for RiskGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            parent_of: HashMap::new(),
        }
    }

    /// Record a process event and optional behavioral edges.
    pub fn record_event(
        &mut self,
        event: &ProcessEvent,
        verdict: &str,
        behavior: &str,
        parent_pid: Option<u32>,
    ) {
        self.nodes.insert(
            event.pid,
            GraphNode {
                pid: event.pid,
                exe: event.exe_path.clone(),
                verdict: verdict.to_string(),
                timestamp: event.timestamp,
            },
        );

        if let Some(ppid) = parent_pid {
            self.parent_of.insert(event.pid, ppid);
            self.edges.push(GraphEdge {
                from_pid: ppid,
                to_pid: event.pid,
                kind: EdgeKind::Spawn,
                weight: 1.0,
            });
        }

        let lower = behavior.to_lowercase();
        if lower.contains("connect") || lower.contains("outbound") || lower.contains("socket") {
            self.edges.push(GraphEdge {
                from_pid: event.pid,
                to_pid: event.pid,
                kind: EdgeKind::Network,
                weight: 0.8,
            });
        }
        if lower.contains("file_touch")
            || lower.contains("openat")
            || lower.contains("/etc/shadow")
            || lower.contains("/etc/passwd")
        {
            self.edges.push(GraphEdge {
                from_pid: event.pid,
                to_pid: event.pid,
                kind: EdgeKind::FileTouch,
                weight: 0.6,
            });
        }

        self.enforce_capacity();
    }

    fn enforce_capacity(&mut self) {
        if self.nodes.len() <= MAX_GRAPH_NODES {
            return;
        }
        let mut by_time: Vec<(u32, u64)> = self
            .nodes
            .iter()
            .map(|(pid, n)| (*pid, n.timestamp))
            .collect();
        by_time.sort_by_key(|(_, ts)| *ts);
        let drop_n = self.nodes.len().saturating_sub(MAX_GRAPH_NODES);
        for (pid, _) in by_time.into_iter().take(drop_n) {
            self.nodes.remove(&pid);
            self.parent_of.remove(&pid);
        }
        self.edges
            .retain(|e| self.nodes.contains_key(&e.from_pid) && self.nodes.contains_key(&e.to_pid));
    }

    /// Score a PID subtree by summing quarantine-weighted node + edge risk.
    pub fn score_subtree(&self, pid: u32) -> f32 {
        let mut score = 0.0f32;
        let mut stack = vec![pid];
        let mut visited = Vec::new();

        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.push(current);

            if let Some(node) = self.nodes.get(&current) {
                if node.verdict.contains("QUARANTINE") {
                    score += 1.0;
                } else if node.verdict.contains("REVIEW") {
                    score += 0.4;
                }
            }

            for edge in &self.edges {
                if edge.from_pid == current && edge.kind == EdgeKind::Spawn {
                    stack.push(edge.to_pid);
                    score += edge.weight * 0.2;
                }
                if edge.from_pid == current && edge.kind == EdgeKind::Network {
                    score += edge.weight * 0.3;
                }
                if edge.from_pid == current && edge.kind == EdgeKind::FileTouch {
                    score += edge.weight * 0.15;
                }
            }
        }
        score
    }

    pub fn export_json(&self) -> String {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            nodes: Vec<&'a GraphNode>,
            edges: &'a [GraphEdge],
        }
        let nodes: Vec<_> = self.nodes.values().collect();
        serde_json::to_string(&Snapshot {
            nodes,
            edges: &self.edges,
        })
        .unwrap_or_else(|_| "{\"nodes\":[],\"edges\":[]}".to_string())
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// Thread-safe wrapper for daemon use.
pub struct SharedRiskGraph(pub RwLock<RiskGraph>);

impl SharedRiskGraph {
    pub fn new() -> Self {
        Self(RwLock::new(RiskGraph::new()))
    }
}

impl Default for SharedRiskGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{EventSource, ProcessEvent};

    fn sample_event(pid: u32, exe: &str) -> ProcessEvent {
        ProcessEvent {
            pid,
            name: "test".into(),
            cmdline: "test".into(),
            exe_path: exe.into(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: None,
        }
    }

    #[test]
    fn records_nodes_and_spawn_edges() {
        let mut g = RiskGraph::new();
        let child = sample_event(200, "/tmp/evil");
        g.record_event(&child, "🚨 QUARANTINE", "spawned_children", Some(100));
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.edges.len(), 1);
        assert!(g.score_subtree(200) >= 1.0);
    }

    #[test]
    fn network_edge_increases_score() {
        let mut g = RiskGraph::new();
        let e = sample_event(10, "/usr/bin/curl");
        g.record_event(&e, "✅ ALLOW", "outbound connect socket", None);
        assert!(g.score_subtree(10) > 0.0);
    }

    #[test]
    fn export_json_is_valid() {
        let mut g = RiskGraph::new();
        g.record_event(&sample_event(1, "/bin/sh"), "✅ ALLOW", "", None);
        let json = g.export_json();
        assert!(json.contains("\"nodes\""));
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn evicts_oldest_when_over_capacity() {
        let mut g = RiskGraph::new();
        for i in 0..(MAX_GRAPH_NODES + 10) {
            let mut e = sample_event(i as u32, "/bin/true");
            e.timestamp = i as u64;
            g.record_event(&e, "✅ ALLOW", "", None);
        }
        assert!(g.node_count() <= MAX_GRAPH_NODES);
    }
}
