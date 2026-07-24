from typing import List, Dict, Any

class RiskScorer:
    def calculate_risk(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        overall_score = 0
        breakdown = {
            "yara": 0,
            "sigma": 0,
            "ioc": 0,
            "suspicious_process": 0,
            "persistence": 0,
            "network_anomaly": 0
        }
        
        for alert in alerts:
            rule_type = alert.get("rule_type", "")
            if rule_type == "yara":
                score = 25
                overall_score += score
                breakdown["yara"] += score
            elif rule_type == "sigma":
                score = 20
                overall_score += score
                breakdown["sigma"] += score
            elif rule_type == "ioc":
                score = 30
                overall_score += score
                breakdown["ioc"] += score
            elif rule_type == "heuristic":
                desc = alert.get("description", "").lower()
                if "suspicious process" in desc:
                    score = 15
                    overall_score += score
                    breakdown["suspicious_process"] += score
                if "persistence" in desc:
                    score = 20
                    overall_score += score
                    breakdown["persistence"] += score
                if "network anomaly" in desc:
                    score = 10
                    overall_score += score
                    breakdown["network_anomaly"] += score
                    
        overall_score = min(100, overall_score)
        
        if overall_score >= 80:
            risk_level = "Critical"
        elif overall_score >= 60:
            risk_level = "High"
        elif overall_score >= 40:
            risk_level = "Medium"
        elif overall_score >= 20:
            risk_level = "Low"
        else:
            risk_level = "Info"
            
        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "breakdown": breakdown
        }

    def get_risk_color(self, score: int) -> str:
        if score >= 80:
            return "#FF0000"  # Red
        elif score >= 60:
            return "#FF9900"  # Orange
        elif score >= 40:
            return "#FFFF00"  # Yellow
        elif score >= 20:
            return "#00FF00"  # Green
        return "#0000FF"      # Blue
