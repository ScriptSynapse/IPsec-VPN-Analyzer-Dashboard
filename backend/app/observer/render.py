"""Markdown renderer for the Observer Profile report."""


def render_observer_profile_markdown(profile: dict) -> str:
    lines = ["# Observer Profile", ""]

    if profile.get("session_id"):
        lines.append(f"**Session:** `{profile['session_id']}`  ")
    if profile.get("tunnel_id"):
        lines.append(f"**Tunnel:** `{profile['tunnel_id']}`  ")
    if profile.get("session_count") is not None:
        lines.append(f"**Sessions in this tunnel:** {profile['session_count']}  ")
    lines.append("")

    findings = profile.get("findings", [])
    if not findings:
        lines.append("No observer findings for this session.")
        return "\n".join(lines) + "\n"

    for finding in findings:
        if finding.get("category") == "insufficient_history":
            lines += [
                "## Multi-session correlation: insufficient history",
                "",
                f"Needs at least {finding['sessions_needed']} sessions sharing a tunnel_id to "
                f"correlate temporal patterns, peer stability, or volume signatures; "
                f"currently have {finding['sessions_have']}.",
                "",
            ]
            continue

        lines += [
            f"## {finding['category'].replace('_', ' ').title()}",
            "",
            finding["description"],
            "",
            f"- **Confidence:** {finding['confidence']:.0%}",
        ]
        if finding.get("mitigation"):
            lines.append(f"- **Mitigation:** {finding['mitigation']}")
        lines.append("")

    return "\n".join(lines) + "\n"
