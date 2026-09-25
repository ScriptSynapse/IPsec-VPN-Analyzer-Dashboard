"""Plain-language executive summary.

Rule-based generation is the only path that has to work reliably for a demo.
An LLM polish pass is an optional stretch add-on: pass an `llm_polish`
callable to rewrite the rule-based text; leave it unset (the default) and the
rule-based summary is returned as-is, so the report endpoint never depends on
an external API being configured or reachable.
"""

from collections.abc import Callable

from app.core.schemas import ScoreResultSchema, SessionSchema

RISK_BANDS = [
    (85, "Low Risk"),
    (65, "Moderate Risk"),
    (40, "High Risk"),
    (0, "Critical Risk"),
]


def _risk_band(overall_score: float) -> str:
    for threshold, label in RISK_BANDS:
        if overall_score >= threshold:
            return label
    return "Critical Risk"


def _rule_based_summary(session: SessionSchema, score: ScoreResultSchema) -> str:
    band = _risk_band(score.overall_score)
    paragraphs = [
        f"This VPN session ({session.filename}) was assessed as **{band}**, "
        f"with an overall security score of {score.overall_score:.0f}/100.",
    ]

    paragraphs.append(
        f"Cryptographic strength scored {score.crypto_strength:.0f}/100, "
        f"policy compliance scored {score.compliance:.0f}/100, key management "
        f"practices scored {score.key_management:.0f}/100, and resistance to "
        f"metadata-based traffic analysis scored {score.metadata_exposure:.0f}/100."
    )

    if score.threat_matrix:
        top = score.threat_matrix[:3]
        findings_text = "; ".join(f"{t.finding} ({t.likelihood.lower()} likelihood)" for t in top)
        paragraphs.append(f"Key findings requiring attention: {findings_text}.")
        paragraphs.append(
            "Recommended next step: " + top[0].recommendation
        )
    else:
        paragraphs.append("No policy violations were identified against the active compliance policy.")

    return "\n\n".join(paragraphs)


def build_executive_report(
    session: SessionSchema,
    score: ScoreResultSchema,
    llm_polish: Callable[[str], str] | None = None,
) -> dict:
    summary = _rule_based_summary(session, score)

    if llm_polish is not None:
        try:
            summary = llm_polish(summary)
        except Exception:
            # LLM polish is a stretch goal; any failure falls back to the
            # rule-based text so the report endpoint never breaks on it.
            pass

    return {
        "session_id": session.id,
        "risk_band": _risk_band(score.overall_score),
        "overall_score": score.overall_score,
        "summary": summary,
    }


def render_executive_markdown(report: dict) -> str:
    return (
        f"# Executive Summary — Session `{report['session_id']}`\n\n"
        f"**Risk band:** {report['risk_band']}  \n"
        f"**Overall score:** {report['overall_score']}/100\n\n"
        f"{report['summary']}\n"
    )
