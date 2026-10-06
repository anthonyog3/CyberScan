def calculate_risk(hash_match: bool, reasons: list[str]) -> tuple[str, int]:
    score = 0

    if hash_match:
        score += 100

    score += min(len(reasons) * 20, 60)

    if score >= 100:
        return "CRITICAL", score
    if score >= 60:
        return "HIGH", score
    if score >= 20:
        return "MEDIUM", score
    return "LOW", score
