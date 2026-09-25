import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

// Self-contained concentric-ring layout: agents (inner ring) -> tunnels
// (middle ring) -> peer IPs (outer ring), mirroring the actual data
// hierarchy (an agent feeds a tunnel, a tunnel observes peers) rather than
// a generic force-directed blob. No charting library -- this project has
// none installed, and a fixed ring layout is simpler to get right than a
// physics simulation for what's fundamentally a 3-tier graph.

const RING_STYLE = {
  agent: { radius: 90, color: "#2563eb", fill: "#eff6ff" },
  tunnel: { radius: 200, color: "#7c3aed", fill: "#f5f3ff" },
  peer: { radius: 300, color: "#059669", fill: "#ecfdf5" },
};

const VIEW_SIZE = 640;
const CENTER = VIEW_SIZE / 2;

function layoutRing(nodes, radius) {
  const positions = {};
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI / 2;
    positions[node.id] = {
      x: CENTER + radius * Math.cos(angle),
      y: CENTER + radius * Math.sin(angle),
    };
  });
  return positions;
}

export function TopologyGraph({ nodes, edges }) {
  const navigate = useNavigate();
  const [hovered, setHovered] = useState(null);

  const positions = useMemo(() => {
    const byType = { agent: [], tunnel: [], peer: [] };
    for (const n of nodes) byType[n.type]?.push(n);
    return {
      ...layoutRing(byType.agent, RING_STYLE.agent.radius),
      ...layoutRing(byType.tunnel, RING_STYLE.tunnel.radius),
      ...layoutRing(byType.peer, RING_STYLE.peer.radius),
    };
  }, [nodes]);

  const neighborIds = useMemo(() => {
    if (!hovered) return null;
    const set = new Set([hovered]);
    for (const e of edges) {
      if (e.source === hovered) set.add(e.target);
      if (e.target === hovered) set.add(e.source);
    }
    return set;
  }, [hovered, edges]);

  function handleNodeClick(node) {
    if (node.type === "tunnel") navigate(`/tunnels/${encodeURIComponent(node.id.replace(/^tunnel:/, ""))}`);
    if (node.type === "agent") navigate("/agents");
  }

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${VIEW_SIZE} ${VIEW_SIZE}`} className="w-full max-w-2xl mx-auto" style={{ minWidth: 480 }}>
        {[RING_STYLE.agent.radius, RING_STYLE.tunnel.radius, RING_STYLE.peer.radius].map((r) => (
          <circle key={r} cx={CENTER} cy={CENTER} r={r} fill="none" stroke="#f1f5f9" strokeWidth="1" />
        ))}

        {edges.map((e, i) => {
          const a = positions[e.source];
          const b = positions[e.target];
          if (!a || !b) return null;
          const dimmed = neighborIds && !(neighborIds.has(e.source) && neighborIds.has(e.target));
          return (
            <line
              key={i}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={dimmed ? "#e2e8f0" : "#94a3b8"}
              strokeWidth={dimmed ? 1 : 1.5}
            />
          );
        })}

        {nodes.map((node) => {
          const pos = positions[node.id];
          if (!pos) return null;
          const style = RING_STYLE[node.type];
          const dimmed = neighborIds && !neighborIds.has(node.id);
          return (
            <g
              key={node.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => handleNodeClick(node)}
              style={{ cursor: node.type === "peer" ? "default" : "pointer", opacity: dimmed ? 0.35 : 1 }}
            >
              <circle r={node.type === "agent" ? 16 : 12} fill={style.fill} stroke={style.color} strokeWidth="2" />
              <text
                y={node.type === "agent" ? 30 : 26}
                textAnchor="middle"
                className="fill-slate-600"
                style={{ fontSize: 10, fontWeight: node.type === "agent" ? 600 : 500 }}
              >
                {node.label.length > 16 ? node.label.slice(0, 15) + "…" : node.label}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="flex justify-center gap-6 mt-2 text-xs text-slate-500">
        {Object.entries(RING_STYLE).map(([type, style]) => (
          <span key={type} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: style.fill, border: `2px solid ${style.color}` }} />
            {type === "agent" ? "Agents" : type === "tunnel" ? "Tunnels" : "Peer IPs"}
          </span>
        ))}
      </div>
    </div>
  );
}
