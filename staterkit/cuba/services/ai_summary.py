"""AI Breach Summary — generates executive summaries from breach data."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def generate_executive_summary(stats, timeline_labels=None, timeline_data=None):
    """Generate a natural language executive summary from breach statistics.

    Args:
        stats: dict with total, by_type, by_source, by_domain
        timeline_labels: list of date labels
        timeline_data: list of counts per period

    Returns:
        dict with title, summary, key_findings, recommendations, risk_level
    """
    total = stats.get('total', 0)
    by_source = stats.get('by_source', {})
    by_domain = stats.get('by_domain', {})
    by_type = stats.get('by_type', {})

    # Determine risk level
    if total > 100000:
        risk_level = 'critical'
        risk_color = '#dc2626'
    elif total > 10000:
        risk_level = 'high'
        risk_color = '#d97706'
    elif total > 1000:
        risk_level = 'medium'
        risk_color = '#4f46e5'
    else:
        risk_level = 'low'
        risk_color = '#059669'

    # Top source analysis
    top_source = max(by_source.items(), key=lambda x: x[1]) if by_source else ('Unknown', 0)
    top_source_pct = round((top_source[1] / max(total, 1)) * 100, 1)

    # Top domain analysis
    top_domains = sorted(by_domain.items(), key=lambda x: x[1], reverse=True)[:5]

    # Trend analysis
    trend_text = 'stable'
    if timeline_data and len(timeline_data) >= 4:
        recent = sum(timeline_data[-2:]) if len(timeline_data) >= 2 else 0
        older = sum(timeline_data[:2]) if len(timeline_data) >= 2 else 0
        if older > 0:
            change = ((recent - older) / older) * 100
            if change > 50:
                trend_text = 'rapidly increasing'
            elif change > 20:
                trend_text = 'increasing'
            elif change < -20:
                trend_text = 'decreasing'
            else:
                trend_text = 'stable'

    # Generate summary paragraphs
    summary = f"The threat intelligence platform has identified a total of {total:,} breached credentials across {len(by_domain)} affected domains from {len(by_source)} distinct sources. "

    if total > 0:
        summary += f"The primary source of breached data is {top_source[0]}, accounting for {top_source_pct}% of all records ({top_source[1]:,} credentials). "

        if len(top_domains) > 0:
            domain_names = ', '.join([d[0] for d in top_domains[:3]])
            summary += f"The most affected domains are {domain_names}. "

        summary += f"The overall breach trend is {trend_text}. "
    else:
        summary += "No breached credentials have been detected in the current monitoring scope. "

    # Key findings
    key_findings = []

    if total > 0:
        key_findings.append({
            'icon': 'shield',
            'color': risk_color,
            'title': f'{total:,} Total Exposed Credentials',
            'desc': f'Across {len(by_domain)} domains and {len(by_source)} sources'
        })

    if top_source[1] > 0:
        key_findings.append({
            'icon': 'alert-triangle',
            'color': '#d97706',
            'title': f'{top_source[0]} is the Primary Source',
            'desc': f'Contributing {top_source_pct}% of all breached credentials'
        })

    if len(top_domains) > 0:
        key_findings.append({
            'icon': 'globe',
            'color': '#4f46e5',
            'title': f'{top_domains[0][0]} is Most Affected',
            'desc': f'With {top_domains[0][1]:,} exposed credentials'
        })

    if trend_text in ('rapidly increasing', 'increasing'):
        key_findings.append({
            'icon': 'trending-up',
            'color': '#dc2626',
            'title': f'Breach Volume is {trend_text.title()}',
            'desc': 'Recent periods show elevated breach activity'
        })
    elif trend_text == 'decreasing':
        key_findings.append({
            'icon': 'trending-down',
            'color': '#059669',
            'title': 'Breach Volume is Decreasing',
            'desc': 'Recent periods show reduced breach activity'
        })

    # Source diversity
    if len(by_source) > 3:
        key_findings.append({
            'icon': 'layers',
            'color': '#7c3aed',
            'title': f'{len(by_source)} Distinct Sources Detected',
            'desc': 'Multiple breach vectors indicate broad exposure'
        })

    # Recommendations
    recommendations = []

    if total > 10000:
        recommendations.append('Initiate immediate credential rotation for all affected domains')

    if len(top_domains) > 0:
        recommendations.append(f'Prioritize remediation for {top_domains[0][0]} ({top_domains[0][1]:,} credentials)')

    if trend_text in ('rapidly increasing', 'increasing'):
        recommendations.append('Increase monitoring frequency — breach volume is trending upward')

    recommendations.append('Enable 2FA for all users with exposed credentials')
    recommendations.append('Review and update watchlist entries for comprehensive coverage')

    if len(by_source) > 1:
        recommendations.append(f'Investigate {top_source[0]} as the dominant breach source')

    recommendations.append('Schedule weekly automated reports for stakeholder visibility')

    return {
        'title': 'Executive Breach Intelligence Summary',
        'generated_at': datetime.now(timezone.utc).strftime('%B %d, %Y %H:%M UTC'),
        'risk_level': risk_level,
        'risk_color': risk_color,
        'summary': summary,
        'key_findings': key_findings,
        'recommendations': recommendations,
        'stats': {
            'total': total,
            'sources': len(by_source),
            'domains': len(by_domain),
            'types': len(by_type),
            'top_source': top_source[0] if top_source else 'N/A',
            'top_domain': top_domains[0][0] if top_domains else 'N/A',
            'trend': trend_text,
        }
    }
