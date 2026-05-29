function matchPoliciesForFindings(policies, keywords) {
  if (!Array.isArray(policies) || !Array.isArray(keywords)) {
    return [];
  }
  
  const matches = [];
  const lowercaseKeywords = keywords.map(k => String(k).toLowerCase());

  for (const policy of policies) {
    const name = (policy.policy_name || "").toLowerCase();
    const desc = (policy.description || "").toLowerCase();
    const rule = (policy.policy_rule || "").toLowerCase();
    const applies = (policy.applies_to || "").toLowerCase();

    for (const kw of lowercaseKeywords) {
      if (kw && (name.includes(kw) || desc.includes(kw) || rule.includes(kw) || applies.includes(kw))) {
        matches.push(policy);
        break;
      }
    }
  }

  return matches;
}

module.exports = { matchPoliciesForFindings };
