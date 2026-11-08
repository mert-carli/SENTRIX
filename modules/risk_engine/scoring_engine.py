from typing import Dict, Any

class ExplainableRiskScorer:
    """Computes transparent, explainable risk scores combining CVSS, EPSS, KEV, and exposure factors."""

    @classmethod
    def calculate_risk(
        cls,
        base_cvss: float,
        epss_score: float = 0.0,
        is_cisa_kev: bool = False,
        is_internet_exposed: bool = True,
        asset_criticality: float = 1.0  # 0.5 (Dev), 1.0 (Standard), 1.5 (Mission-Critical / DC)
    ) -> Dict[str, Any]:
        """
        Risk = (Base_CVSS * 0.4 + EPSS_Weighted * 0.3 + KEV_Factor * 0.3) * Exposure_Factor * Asset_Criticality
        Normalized to 0.0 - 100.0 scale.
        """
        cvss_component = min(10.0, max(0.0, base_cvss)) * 10.0  # 0 to 100
        epss_component = min(1.0, max(0.0, epss_score)) * 100.0  # 0 to 100
        kev_component = 100.0 if is_cisa_kev else 0.0

        # Weighted combination
        raw_score = (cvss_component * 0.45) + (epss_component * 0.25) + (kev_component * 0.30)

        # Exposure multiplier
        exposure_multiplier = 1.0 if is_internet_exposed else 0.6
        final_score = min(100.0, raw_score * exposure_multiplier * asset_criticality)

        # Severity categorization
        if final_score >= 80.0:
            rating = "CRITICAL"
        elif final_score >= 60.0:
            rating = "HIGH"
        elif final_score >= 40.0:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "overall_score": round(final_score, 1),
            "rating": rating,
            "components": {
                "cvss_component": round(cvss_component, 1),
                "epss_component": round(epss_component, 1),
                "kev_component": kev_component,
                "exposure_multiplier": exposure_multiplier,
                "criticality_multiplier": asset_criticality
            },
            "explanation": f"Score {final_score:.1f} ({rating}) driven by CVSS {base_cvss:.1f}, EPSS {epss_score:.2%}, and KEV status {'Active' if is_cisa_kev else 'None'}."
        }
