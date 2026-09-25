"""Structured technical report assembly (JSON dict + markdown rendering)."""

from app.core.schemas import (
    FlowFindingSchema,
    IkeFindingSchema,
    ScoreResultSchema,
    SessionSchema,
)


def build_technical_report(
    session: SessionSchema,
    ike_finding: IkeFindingSchema,
    flow_findings: list[FlowFindingSchema],
    score: ScoreResultSchema,
) -> dict:
    proposal = ike_finding.proposals[0] if ike_finding.proposals else None

    return {
        "session": session.model_dump(mode="json"),
        "ike": {
            "ike_version": ike_finding.ike_version,
            "exchange_type": ike_finding.exchange_type,
            "chosen_proposal": proposal.model_dump(mode="json") if proposal else None,
            "all_proposals": [p.model_dump(mode="json") for p in ike_finding.proposals],
            "pfs_enabled": ike_finding.pfs_enabled,
            "sa_lifetime": ike_finding.sa_lifetime,
            "implementation_guess": ike_finding.implementation_guess,
            "vendor_ids": ike_finding.vendor_ids,
        },
        "flows": [f.model_dump(mode="json") for f in flow_findings],
        "score": score.model_dump(mode="json"),
    }


def render_technical_markdown(report: dict) -> str:
    session = report["session"]
    ike = report["ike"]
    score = report["score"]
    proposal = ike.get("chosen_proposal") or {}

    lines = [
        f"# Technical Report — Session `{session['id']}`",
        "",
        f"- **File:** {session['filename']}",
        f"- **Mode:** {session.get('mode') or 'unknown'}",
        f"- **IP version:** {session.get('ip_version') or 'unknown'}",
        f"- **Captured:** {session['created_at']}",
        "",
        "## IKE Handshake",
        "",
        f"- **IKE version:** {ike.get('ike_version') or 'unknown'}",
        f"- **Exchange type:** {ike.get('exchange_type') or 'unknown'}",
        f"- **Encryption:** {proposal.get('encryption_alg') or 'unknown'}",
        f"- **Integrity:** {proposal.get('auth_alg') or 'unknown'}",
        f"- **DH group:** {proposal.get('dh_group') or 'unknown'}",
        f"- **PFS enabled:** {ike.get('pfs_enabled')}",
        f"- **SA lifetime (s):** {proposal.get('lifetime_seconds') or 'unknown'}",
        f"- **Implementation guess:** {ike.get('implementation_guess') or 'unknown'}",
        "",
        "## Flow Findings (encrypted ESP traffic, side-channel inference only)",
        "",
        "| Flow | Predicted type | Confidence | Packets | Avg size (B) | Duration (s) |",
        "|---|---|---|---|---|---|",
    ]

    for flow in report["flows"]:
        lines.append(
            f"| {flow['flow_key']} | {flow['predicted_traffic_type']} | "
            f"{flow['confidence']:.2f} | {flow['packet_count']} | "
            f"{flow['avg_packet_size']:.1f} | {flow['duration_s']:.2f} |"
        )

    lines += [
        "",
        "## Security Score",
        "",
        f"- **Crypto strength:** {score['crypto_strength']}/100",
        f"- **Compliance:** {score['compliance']}/100",
        f"- **Key management:** {score['key_management']}/100",
        f"- **Metadata exposure resistance:** {score['metadata_exposure']}/100",
        f"- **Overall score:** {score['overall_score']}/100",
        "",
        "## Threat Matrix",
        "",
        "| Finding | Likelihood | Impact | Recommendation |",
        "|---|---|---|---|",
    ]

    for threat in score["threat_matrix"]:
        lines.append(
            f"| {threat['finding']} | {threat['likelihood']} | {threat['impact']} | "
            f"{threat['recommendation']} |"
        )

    return "\n".join(lines) + "\n"
