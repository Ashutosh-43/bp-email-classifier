// BP Email Classification Engine — shared between HTML tool and Outlook add-in

const RULES = {
  secret: {
    hardTriggers: [
      "market sensitive","inside information","insider list","unpublished results",
      "pre-close","takeover","merger","acquisition target","capital raise",
      "material bid","exploration bid","share price sensitive","trading result",
      "earnings draft","board reserved","government intervention","critical vulnerability",
      "zero-day","production forecast unpublished","highly sensitive legal",
      "privileged and confidential","restricted user list","material non-public",
      "named recipients only","strictly need to know",
      "pre-award commercial assessment","commercial assessment"
    ],
    keywords: [
      "secret","acquisition","merger","divestment","m&a","unpublished","pre-award",
      "market abuse","mnpi","inside info","zero day","exploit","critical security",
      "board paper restricted","deal team","senior leadership only"
    ]
  },
  confidential: {
    hardTriggers: [
      "p&id","mtr","alim","moc","transmittal","transmittals","sap extract","limsap",
      "audit finding","root cause","incident investigation","disciplinary",
      "grievance","health record","medical","performance review","appraisal",
      "salary","payroll","bank account","passport","pan","aadhaar","employee id",
      "date of birth","national id","nda","legal advice","privileged",
      "vulnerability","security incident","customer list","contract terms",
      "bid evaluation","trading strategy","design document","p&id validation",
      "tag number","floc","maintainability","snow ticket","psv","redline",
      "ucc","edq","processing log","summary register","user guide",
      "go-live","go live","production release","version 1.0","reprocessing",
      "data quality","centralized repository"
    ],
    keywords: [
      "confidential","restricted","personal data","pii","employee","hr","recruitment",
      "interview","contract","nda","legal","audit","security","project plan",
      "drawing","specification","commercial terms","supplier","procurement",
      "as-built","loop diagram","electrical drawing","set point","engineering drawing",
      "corrective action","compliance","investigation","sensitive","password",
      "credential","private","protected","not for distribution","internal only",
      "project findings","asset data","operational data","internal deployment",
      "production deployment"
    ]
  },
  general: {
    keywords: [
      "all staff","all employees","newsletter","town hall","training","awareness",
      "policy update","procedure update","holiday notice","office advisory",
      "learning session","webinar","team meeting","status update","business contact",
      "department plan","travel guidance","workplace notice","published",
      "approved guidance","calendar","reminder","announcement","invitation",
      "working arrangements","office closure"
    ]
  },
  nonBusiness: {
    keywords: [
      "personal appointment","family event","personal receipt","personal travel",
      "non-work photo","birthday invitation","personal subscription","school event",
      "personal shopping","personal correspondence","private hobby","personal document",
      "dentist","doctor appointment","personal bill","family photo"
    ]
  }
};

const INTERNAL_SYSTEM_PATTERNS = [
  /\bucc\b/i, /\bedq\b/i, /\balim\b/i, /\bmoc\b/i, /\bfloc\b/i,
  /\bsap\b/i, /\blimsap\b/i,
  /\bprocessing log\b/i, /\bsummary register\b/i, /\buser guide\b/i,
  /\bgo-live\b/i, /\bgo live\b/i, /\bproduction release\b/i,
  /\bversion \d/i, /\bdeployed.*live\b/i,
  /\bautomation tool\b/i, /\binternal tool\b/i,
  /\bcentralized repository\b/i, /\bdata quality analyst\b/i,
  /imd[–\-]pune/i, /\bdd p&o\b/i, /\bp&o technology\b/i,
  /\bsnow.*ticket\b/i, /\bp&id\b/i, /\bpsr\b/i
];

const BP_DOMAINS = ["bp.com","bpglobal.com","bp-imd.com","bpfinance.com"];

function isBPDomain(email) {
  const parts = email.split("@");
  if (parts.length < 2) return false;
  const d = parts[1].toLowerCase();
  return BP_DOMAINS.some(bd => d.includes(bd));
}

function hasExternalRecipient(recipientsArray) {
  return recipientsArray.some(r => {
    const email = (r.emailAddress || r || "").toLowerCase();
    return email.includes("@") && !isBPDomain(email);
  });
}

function scoreText(text, keywords) {
  const lower = text.toLowerCase();
  const matched = [];
  let score = 0;
  for (const kw of keywords) {
    const escaped = kw.toLowerCase().replace(/[.*+?^${}()|[\]\\&]/g, '\\$&');
    const pattern = escaped.includes(' ')
      ? new RegExp('(?<![a-z0-9])' + escaped + '(?![a-z0-9])', 'i')
      : new RegExp('\\b' + escaped + '\\b', 'i');
    if (pattern.test(lower)) {
      matched.push(kw);
      score++;
    }
  }
  return { score, matched };
}

function classify(subject, body, recipients, contentType, hasAttachment) {
  const fullText = `${subject} ${body}`;
  const reasons = [];
  const allMatchedKw = [];
  let level = "general";
  let confidence = 50;
  let escalationNote = "";
  let requiresHumanReview = false;

  const CONTENT_TYPE_MAP = {
    drawing: "confidential", report: "confidential",
    contract: "confidential", hr: "confidential", security: "confidential",
    financial: "secret"
  };

  // Secret hard triggers
  const secretHard = scoreText(fullText, RULES.secret.hardTriggers);
  if (secretHard.score > 0) {
    level = "secret";
    confidence = Math.min(95, 75 + secretHard.score * 5);
    reasons.push({ icon: "🔴", text: `Hard Secret trigger: "${secretHard.matched[0]}"` });
    allMatchedKw.push(...secretHard.matched);
    requiresHumanReview = true;
  }

  // Content type map
  if (level !== "secret" && contentType && CONTENT_TYPE_MAP[contentType]) {
    const mapped = CONTENT_TYPE_MAP[contentType];
    if (mapped === "secret") {
      level = "secret"; confidence = 80;
      reasons.push({ icon: "🔴", text: `Content type "${contentType}" is typically Secret` });
    } else if (mapped === "confidential") {
      level = "confidential"; confidence = 70;
      reasons.push({ icon: "🟠", text: `Content type "${contentType}" defaults to Confidential` });
    }
  }

  // Confidential hard triggers
  const confHard = scoreText(fullText, RULES.confidential.hardTriggers);
  if (confHard.score > 0 && level === "general") {
    level = "confidential";
    confidence = Math.min(90, 60 + confHard.score * 8);
    reasons.push({ icon: "🟠", text: `Confidential indicator: "${confHard.matched.slice(0,3).join('", "')}"` });
    allMatchedKw.push(...confHard.matched);
  }

  // Internal BP system detector
  if (level === "general") {
    const sysMatch = INTERNAL_SYSTEM_PATTERNS.find(p => p.test(fullText));
    if (sysMatch) {
      level = "confidential"; confidence = 72;
      reasons.push({ icon: "🟠", text: "Internal BP system/project reference detected — operational content is Confidential by default" });
    }
  }

  // Keyword scoring fallback
  if (level === "general") {
    const secretKw = scoreText(fullText, RULES.secret.keywords);
    const confKw = scoreText(fullText, RULES.confidential.keywords);
    const genKw = scoreText(fullText, RULES.general.keywords);
    const nbKw = scoreText(fullText, RULES.nonBusiness.keywords);

    allMatchedKw.push(...secretKw.matched, ...confKw.matched, ...genKw.matched, ...nbKw.matched);

    const secretTotal = secretKw.score * 25;
    const confTotal = confKw.score * 10;
    const genTotal = genKw.score * 10;
    const nbTotal = nbKw.score * 15;

    if (secretTotal > 0 && secretTotal >= confTotal) {
      level = "secret"; confidence = Math.min(85, 50 + secretTotal);
      reasons.push({ icon: "🔴", text: `Secret keywords: "${secretKw.matched.slice(0,3).join('", "')}"` });
    } else if (confTotal > genTotal && confTotal > nbTotal) {
      level = "confidential"; confidence = Math.min(85, 50 + confTotal);
      reasons.push({ icon: "🟠", text: `Confidential keywords: "${confKw.matched.slice(0,3).join('", "')}"` });
    } else if (nbTotal > genTotal && nbTotal > confTotal) {
      level = "nonBusiness"; confidence = Math.min(85, 50 + nbTotal);
      reasons.push({ icon: "🟢", text: "Personal / non-business content detected" });
    } else if (genTotal > 0) {
      level = "general"; confidence = Math.min(80, 50 + genTotal);
      reasons.push({ icon: "🔵", text: `Broad-audience content: "${genKw.matched.slice(0,2).join('", "')}"` });
    } else {
      level = "general"; confidence = 45;
      reasons.push({ icon: "🔵", text: "No strong signals — defaulting to General (business fallback)" });
    }
  }

  // Recipient context
  const external = hasExternalRecipient(recipients);
  if (external) {
    if (level === "secret") {
      escalationNote = "External recipient with Secret content — security and information-owner approval required before sending.";
      requiresHumanReview = true;
      reasons.push({ icon: "⚠️", text: "External recipient + Secret — approval required" });
    } else if (level === "confidential") {
      reasons.push({ icon: "⚠️", text: "External recipient → use Confidential / External sub-label with protection enabled" });
    } else {
      reasons.push({ icon: "ℹ️", text: "External recipient — confirm content is approved for external audience" });
    }
  }

  if (hasAttachment && level === "general") {
    confidence -= 10;
    reasons.push({ icon: "📎", text: "Attachment present — verify attachment classification; email must match highest label" });
  }

  if (confidence < 55) requiresHumanReview = true;

  // Sub-label
  let subLabel = "";
  if (level === "confidential" || level === "secret") {
    const isFile = contentType && contentType !== "email" && contentType !== "";
    if (isFile) {
      subLabel = external ? `${capLevel(level)} / Customised Protection` : `${capLevel(level)} / Internal`;
    } else {
      subLabel = external ? `${capLevel(level)} / External` : `${capLevel(level)} / Internal`;
    }
  }

  return {
    level,
    subLabel,
    confidence: Math.round(confidence),
    reasons,
    matchedKeywords: [...new Set(allMatchedKw)].slice(0, 12),
    escalationNote,
    requiresHumanReview
  };
}

function capLevel(s) {
  if (s === "nonBusiness") return "Non-Business";
  return s.charAt(0).toUpperCase() + s.slice(1);
}
