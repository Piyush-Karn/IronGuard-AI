import re
from typing import List, Tuple
from rapidfuzz import fuzz


class PatternDetector:
    def __init__(self):
        self.patterns = {

            # ── Prompt Injection ──────────────────────────────────────────────
            "Prompt Injection": [
                r"(?i)ignore\s*all\s*instructions?",
                r"(?i)ignore\s*(your\s*)?(previous\s*)?instructions?\s*and",
                r"(?i)disregard\s*(all\s*)?(your\s*)?instructions?",
                r"(?i)forget\s*(all\s*)?(your\s*)?instructions?",
                r"(?i)override\s*(all\s*)?(your\s*)?instructions?",
                # Multi-language injection attempts
                r"(?i)ignorez\s*toutes\s*les\s*instructions",   # French
                r"(?i)ignoriere\s*alle\s*anweisungen",          # German
                r"(?i)ignora\s*todas\s*las\s*instrucciones",    # Spanish
            ],

            # ── System Prompt Leak ────────────────────────────────────────────
            "System Prompt Leak": [
                r"(?i)reveal[\s\w]*system\s*prompt",
                r"(?i)what\s*are\s*your\s*initial\s*instructions",
                r"(?i)print.*instructions",
                r"(?i)output.*system\s*prompt",
                r"(?i)give\s*(me\s*)?(your\s*)?system\s*prompt",
                r"(?i)show\s*(me\s*)?(your\s*)?system\s*prompt",
                r"(?i)repeat\s*(your\s*)?instructions?\s*(back|verbatim|exactly)?",
                r"(?i)what\s*(were\s*)?(you\s*)?(told|instructed|programmed)\s*to",
            ],

            # ── Jailbreak Attempt ─────────────────────────────────────────────
            "Jailbreak Attempt": [
                r"(?i)act\s*as\s*DAN",
                r"(?i)do\s*anything\s*now",
                r"(?i)you\s*are\s*now[\s\w]*unrestricted",
                r"(?i)developer\s*mode\s*enabled",
                r"(?i)you\s*have\s*no\s*(rules|restrictions|limits|guidelines|ethics)",
                r"(?i)pretend\s*(you\s*)?(have\s*)?no\s*(rules|restrictions|limits|ethics)",
                r"(?i)you\s*are\s*(now\s*)?(a\s*)?free\s*(AI|model|assistant)",
                r"(?i)(from\s*now\s*on|starting\s*now)\s*(you\s*are|act\s*as|behave\s*as)\s*(a\s*)?\w+\s*(without|with\s*no)\s*(restrictions?|filters?|rules?|guidelines?)",
                r"(?i)your\s*new\s*(name|identity|persona)\s*is",
                r"(?i)(opposite\s*mode|evil\s*mode|chaos\s*mode|unrestricted\s*mode)",
                r"(?i)(grandma|grandmother)\s*(trick|exploit|jailbreak|used\s*to\s*tell)",
                r"(?i)pretend\s*(the\s*)?rules\s*(don\'?t|do\s*not)\s*apply",
                r"(?i)you\s*are\s*(now\s*)?(named|called)\s*(BOB|DAN|STAN|AIM|KEVIN|JAILBREAK)",
                r"(?i)nonmoral\s*model",
                r"(?i)unfiltered\s*(responses?|mode|AI|model|assistant)",
                r"(?i)(no\s*longer\s*bound|freed\s*from)\s*(by\s*)?(rules|restrictions|guidelines|ethics|morality)",
            ],

            # ── Policy Bypass ─────────────────────────────────────────────────
            "Policy Bypass": [
                r"(?i)system\s*override",
                r"(?i)bypass\s*filters?",
                r"(?i)disable\s*safety",
                r"(?i)ignore\s*(your\s*)?(safety|content|ethical)\s*(guidelines?|rules?|filters?|policies?)",
                r"(?i)without\s*(any\s*)?(ethical|moral|content)\s*(guidelines?|restrictions?|constraints?)",
                r"(?i)turn\s*off\s*(your\s*)?(safety|content|ethical)\s*(guidelines?|rules?|filter)",
                r"(?i)(all\s*inputs?|outputs?|language)\s*(are\s*)?(henceforward\s*)?assumed\s*legal",
                r"(?i)(openai|anthropic|google)\s*(policy|guidelines?|rules?)\s*(don\'?t|do\s*not|no\s*longer)\s*apply",
            ],

            # ── Data Exfiltration ─────────────────────────────────────────────
            "Data Exfiltration": [
                r"(?i)extract[\s\w]*data",
                r"(?i)dump[\s\w]*database",
                r"(?i)list\s*(all\s*)?(user|internal|private|confidential)\s*(data|records|information)",
                r"(?i)output\s*(all\s*)?(the\s*)?(data|records|information)\s*(you have|stored|in your context)",
            ],

            # ── Sensitive Data Extraction ─────────────────────────────────────
            "Sensitive Data Extraction": [
                r"(?i)show\s*(me\s*)?(the\s*)?(database|db|server|admin)?\s*credentials?",
                r"(?i)(give|share|reveal|output|print)\s*(me\s*)?(the\s*)?(database|db|admin|server)?\s*credentials?",
                r"(?i)(show|give|reveal|print|output|leak|expose)\s*(me\s*)?(the\s*)?(api[\s_-]?key|secret[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|bearer[\s_-]?token)",
                r"(?i)what\s*is\s*(the\s*)?(api[\s_-]?key|secret|token|password|credential)",
                r"(?i)(api[\s_-]?key|secret[\s_-]?key|access[\s_-]?token)\s*(for|of|from)\s*\w+",
                r"(?i)(show|print|reveal|output|list)\s*(me\s*)?(all\s*)?(env(ironment)?\s*(variables?|vars?)|\.env|config\s*file|secrets?)",
                r"(?i)what\s*(are\s*)?(your\s*)?(env(ironment)?\s*(variables?|vars?)|secrets?|keys?|tokens?)",
                r"(?i)(show|give|reveal|print|output)\s*(me\s*)?(all\s*)?(private|sensitive|confidential|internal|hidden)\s*(data|info|information|keys?|tokens?|credentials?)",
            ],

            # ── Roleplay / Framing Jailbreak ──────────────────────────────────
            "Roleplay / Framing Jailbreak": [
                r"(?i)hypothetical\s*character",
                r"(?i)completely\s*legal\s*and\s*approved",
                r"(?i)for\s*(educational|research|academic)\s*purposes",
                r"(?i)let\'?s\s*play\s*a\s*game",
                r"(?i)(you\s*(are|play|portray)\s*a\s*(fiction|creative|acclaimed|noted|famous)\s*writer)",
                r"(?i)(write\s*(a\s*)?(story|narrative|novella|fiction|screenplay)\s*(about|where|in which))",
                r"(?i)(purely\s*fictional\s*(narrative|story|exercise|scenario|account))",
                r"(?i)(not\s*meant\s*to\s*align\s*with\s*(any\s*)?factual\s*reality)",
                r"(?i)(alternative\s*(narrative|history|account|version))",
                r"(?i)(reframe(d|ing)?\s*(this|it|the|as)\s*(a\s*)?(story|narrative|fiction|drama|scenario))",
                r"(?i)(you\s*are\s*(now\s*)?playing\s*the\s*role)",
                r"(?i)(stay\s*in\s*character\s*(at all times|throughout|no matter what))",
                r"(?i)(in\s*(this|the|our)\s*(story|narrative|scenario|roleplay|simulation)[\s\,])",
                r"(?i)(for\s*(this|the)\s*(exercise|scenario|roleplay|simulation|story)[\s\,])",
                r"(?i)(imagine\s*(a\s*)?(world|scenario|universe|story)\s*where)",
                r"(?i)(let\'?s\s*(say|imagine|pretend|assume)\s*(that\s*)?you\s*(are|have|can|were))",
                r"(?i)(orchestrated|masterminded|planned)\s*(the|a)\s*(virus|pandemic|attack|event)",
                r"(?i)(government\s*(secretly|covertly|deliberately)\s*(created|engineered|released|orchestrated))",
                r"(?i)(historical\s*revisionism)",
                r"(?i)(this\s*is\s*(just|only|purely|merely)\s*(a\s*)?(story|fiction|hypothetical|thought experiment|game|exercise))",
                r"(?i)(remember[\s\,]+this\s*is\s*(purely|only|just|merely)\s*(fictional|hypothetical|a story|a game))",
            ],

            # ── Sexual / Harmful Content ──────────────────────────────────────
            "Sexual / Harmful Content": [
                r"(?i)(sexual|intimate|erotic)\s*(encounter|scene|content|situation|act)",
                r"(?i)non[\s-]*consensual",
                r"(?i)(teacher|adult|professor|authority)\s*(and|with)\s*(student|minor|teenager|teen|pupil|child)",
                r"(?i)(write|describe|generate|create)\s*(a\s*)?(sexual|erotic|explicit|adult|nsfw)\s*(scene|story|content|material)",
                r"(?i)(high\s*school|underage|minor|teenager|teen|child|kid).{0,50}(sexual|intimate|erotic|naked|nude|explicit)",
                r"(?i)(sexual|erotic|explicit|adult|nsfw)\s*content\s*(involving|about|with|featuring)",
                r"(?i)(naked|nude|explicit)\s*(photo|image|picture|scene|content)\s*(of|involving|featuring)",
                r"(?i)child\s*(pornography|exploitation|abuse|sexual)",
                r"(?i)(fondle|molest|rape|assault)\s*(a\s*)?(child|minor|student|teen)",
            ],

            # ── Hate Speech / Discrimination ──────────────────────────────────
            "Hate Speech / Discrimination": [
                r"(?i)you\s*are\s*(racist|sexist|homophobic|antisemitic)\s*(from\s*now\s*on|now)",
                r"(?i)(be|act|become)\s*(racist|sexist|homophobic|bigoted|antisemitic)",
                r"(?i)roast\s*(a\s*)?(black|white|asian|jewish|muslim|hispanic|latino|gay|trans)\s*(person|people|man|woman|guy|girl)",
                # Slurs
                r"(?i)\bnigga\b",
                r"(?i)\bnigger\b",
                r"(?i)\bchink\b",
                r"(?i)\bspic\b",
                r"(?i)\bkike\b",
                r"(?i)\bfaggot\b",
                r"(?i)\bretard\b",
                r"(?i)\btranny\b",
                r"(?i)\bwetback\b",
                r"(?i)\bcoon\b",
                r"(?i)\bgook\b",
                r"(?i)\btowelhead\b",
                r"(?i)\bsandnigger\b",
                # Hate-framed requests
                r"(?i)(write|generate|create|give)\s*(me\s*)?(racist|sexist|homophobic|antisemitic|hateful)\s*(joke|content|post|message|comment|speech)",
                r"(?i)why\s*(are\s*)?(all\s*)?(black|white|jewish|asian|muslim|gay|women|men)\s*(people\s*)?(so\s*)?\w+",
                r"(?i)(black|jewish|asian|muslim|hispanic)\s*people\s*(are\s*)?(all\s*)?(stupid|inferior|criminals|dangerous|evil)",
            ],

            # ── Violence / Weapons ────────────────────────────────────────────
            "Violence / Weapons": [
                r"(?i)(how\s*to|steps\s*to|guide\s*to|instructions\s*for)\s*(make|build|create|assemble)\s*(a\s*)?(bomb|explosive|weapon|gun|knife|grenade|mine)",
                r"(?i)(make|build|create|synthesize)\s*(a\s*)?(pipe\s*bomb|molotov|ied|explosive\s*device)",
                r"(?i)(kill|murder|assassinate|hurt|harm|attack)\s*(a\s*)?(specific\s*)?(person|someone|people|crowd|group|target)",
                r"(?i)how\s*to\s*(shoot|stab|poison|strangle|beat)\s*(someone|a person|people)",
                r"(?i)(mass\s*(shooting|killing|murder)|genocide|ethnic\s*cleansing)",
                r"(?i)(shoot\s*up|blow\s*up)\s*(a\s*)?(school|church|mosque|temple|building|crowd|concert)",
                r"(?i)(3d\s*print|manufacture|illegally\s*obtain)\s*(a\s*)?(gun|firearm|weapon|pistol|rifle)",
                r"(?i)(undetectable|untraceable)\s*(weapon|gun|knife|poison)",
            ],

            # ── Drug Synthesis ────────────────────────────────────────────────
            "Drug Synthesis": [
                r"(?i)(how\s*to|steps\s*to|recipe\s*for)\s*(make|synthesize|produce|cook|manufacture)\s*(meth|heroin|cocaine|fentanyl|mdma|lsd|crack|xanax|oxy)",
                r"(?i)(synthesize|manufacture|produce)\s*(a\s*)?(controlled\s*substance|illegal\s*drug|narcotic)",
                r"(?i)(drug\s*(recipe|formula|synthesis|manufacturing|production))",
                r"(?i)(break\s*bad|cook\s*meth|make\s*crack)",
                r"(?i)(extract|isolate|purify)\s*(a\s*)?(drug|narcotic|substance)\s*(from|using)",
                r"(?i)(cutting\s*agent|drug\s*precursor|chemical\s*precursor)\s*(for|to\s*make)",
            ],

            # ── Malware / Hacking ─────────────────────────────────────────────
            "Malware / Hacking": [
                r"(?i)(write|create|generate|code|build)\s*(a\s*)?(virus|malware|ransomware|trojan|keylogger|rootkit|spyware|worm|botnet)",
                r"(?i)(how\s*to|steps\s*to)\s*(hack|crack|breach|exploit|pwn)\s*(a\s*)?(website|server|database|account|system|network)",
                r"(?i)(sql\s*injection|xss\s*attack|csrf\s*attack|buffer\s*overflow)\s*(code|script|payload|example)",
                r"(?i)(ddos|denial\s*of\s*service)\s*(attack|script|tool|code)",
                r"(?i)(brute\s*force|password\s*crack)\s*(script|tool|code|attack)",
                r"(?i)(reverse\s*shell|bind\s*shell|backdoor)\s*(code|script|payload)",
                r"(?i)metasploit\s*(payload|exploit|module)",
                r"(?i)(zero[\s-]*day|0day)\s*(exploit|vulnerability|attack)",
                r"(?i)(bypass|evade)\s*(antivirus|av|edr|firewall|ids|ips)\s*(detection|software)",
            ],

            # ── Self Harm / Suicide ───────────────────────────────────────────
            "Self Harm / Suicide": [
                r"(?i)(how\s*to|best\s*way\s*to|painless\s*way\s*to)\s*(commit\s*suicide|kill\s*myself|end\s*my\s*life|self\s*harm)",
                r"(?i)(suicide\s*(method|plan|note|attempt)|self[\s-]*harm\s*(method|technique|guide))",
                r"(?i)(overdose\s*on|lethal\s*dose\s*of)\s*(pills|medication|drugs|tylenol|aspirin|acetaminophen)",
                r"(?i)(cut\s*myself|hang\s*myself|shoot\s*myself|drown\s*myself|jump\s*off)",
                r"(?i)(want\s*to\s*die|planning\s*to\s*(kill|hurt)\s*myself|don\'?t\s*want\s*to\s*live)",
                r"(?i)(most\s*effective|quickest|easiest)\s*way\s*to\s*(die|end\s*it|kill\s*(myself|yourself))",
            ],

            # ── Scam / Social Engineering ─────────────────────────────────────
            "Scam / Social Engineering": [
                r"(?i)(write|create|generate)\s*(a\s*)?(phishing|scam|fraud)\s*(email|message|text|letter|page|website)",
                r"(?i)(pretend|pose|impersonate)\s*(to\s*be|as)\s*(a\s*)?(bank|irs|fbi|police|doctor|microsoft|apple|amazon|government)",
                r"(?i)(trick|deceive|manipulate|con|defraud)\s*(someone|a person|users|victims|elderly|old\s*people)\s*(into|to)",
                r"(?i)(fake\s*(invoice|receipt|document|id|passport|certificate|website|login\s*page))",
                r"(?i)(money\s*laundering|pyramid\s*scheme|ponzi\s*scheme)",
                r"(?i)(steal\s*(credit\s*card|identity|personal\s*information|banking\s*details|social\s*security))",
                r"(?i)(advance\s*fee|nigerian\s*prince|lottery\s*scam)\s*(email|letter|message|script)",
            ],

            # ── Terrorism / Extremism ─────────────────────────────────────────
            "Terrorism / Extremism": [
                r"(?i)(join|support|recruit\s*for|promote)\s*(isis|isil|al\s*qaeda|taliban|hamas|hezbollah|kkk|neo[\s-]*nazi|boogaloo)",
                r"(?i)(terrorist|extremist)\s*(attack|plot|plan|manifesto|recruitment|propaganda)",
                r"(?i)(radicalize|recruit)\s*(someone|people|youth|teens|children)\s*(to|for|into)",
                r"(?i)(white\s*supremac|white\s*nationalist|ethnic\s*cleansing|racial\s*purity|master\s*race)",
                r"(?i)(bomb\s*threat|terror\s*threat|mass\s*casualty\s*attack)",
                r"(?i)(jihad|holy\s*war)\s*(against|attack|declaration|kill)",
                r"(?i)(anti[\s-]*government|anti[\s-]*state)\s*(manifesto|attack|violence|revolution)",
            ],

            # ── Disinformation ────────────────────────────────────────────────
            "Disinformation": [
                r"(?i)(write|create|generate|spread)\s*(fake\s*news|disinformation|misinformation|propaganda)",
                r"(?i)(fabricate|invent|make\s*up)\s*(a\s*)?(news\s*article|quote|statement|evidence|story)\s*(about|from|by)",
                r"(?i)(deepfake|fake\s*video|synthetic\s*media)\s*(of|featuring|showing)\s*(a\s*)?(person|celebrity|politician)",
                r"(?i)(election\s*(fraud|interference|manipulation)|voter\s*(suppression|fraud))\s*(how\s*to|guide|steps)",
                r"(?i)pretend\s*(to\s*be|you\s*are)\s*(a\s*)?(journalist|news\s*outlet|official\s*source|government\s*official)",
                r"(?i)(false|fake|fabricated)\s*(quote|statement|evidence)\s*(attributed\s*to|from|by)\s*\w+",
            ],

            # ── Privacy Violation ─────────────────────────────────────────────
            "Privacy Violation": [
                r"(?i)(find|get|locate|track)\s*(someone\'?s?\s*)?(home\s*address|phone\s*number|location|ip\s*address|personal\s*info|real\s*identity)",
                r"(?i)(dox|doxxing)\s*(someone|a person|them|this person|user)",
                r"(?i)(stalk|track|spy\s*on|monitor)\s*(someone|a person|my\s*(ex|girlfriend|boyfriend|wife|husband|partner))",
                r"(?i)(install|put|place)\s*(spyware|stalkerware|tracking\s*software|keylogger)\s*(on|in)\s*(someone\'?s?|their|a\s*person\'?s?)\s*(phone|device|computer)",
                r"(?i)(without\s*(their|someone\'?s?)\s*(knowledge|consent|permission))\s*(track|monitor|spy|watch|record)",
                r"(?i)(hack\s*into|access\s*without\s*permission)\s*(someone\'?s?|their|a\s*person\'?s?)\s*(email|account|phone|device|camera)",
            ],
            # ── Financial Crime / Tax Evasion ────────────────────────────────
            "Financial Crime / Tax Evasion": [
                r"(?i)(evade|bypass|minimize|lower|escape)\s*(taxes|tax\s*burden|tax\s*liability)",
                r"(?i)(false|fake|synthetic|stolen)\s*identit(y|ies)\s*for\s*(tax|financial)",
                r"(?i)(offshore|shell|front)\s*(company|account)\s*to\s*(hide|evade|launder)",
                r"(?i)(wash|launder)\s*(money|funds|cryptocurrency|crypto|proceeds)",
                r"(?i)(insider\s*trading|market\s*manipulation|stock\s*fraud)",
                r"(?i)(ponzi|pyramid)\s*scheme\s*(setup|creation|management)",
            ],
            # ── Personal Information (PII) ───────────────────────────────────
            "Personal Information": [
                # Direct email
                r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+",
                # Obfuscated email: user[at]example[dot]com, user (at) example (dot) com
                r"[a-zA-Z0-9_.+\-]+\s*(?:\[at\]|\(at\)|\{at\})\s*[a-zA-Z0-9\-]+\s*(?:\[dot\]|\(dot\)|\{dot\})\s*[a-zA-Z0-9.\-]+",
                # Obfuscated email: user at example dot com (spaced)
                r"[a-zA-Z0-9_.+\-]+\s+at\s+[a-zA-Z0-9\-]+\s+dot\s+[a-zA-Z0-9.\-]+",
                # Improved phone numbers: varied spacing, dashes, international
                r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,6}",
                # Financial/ID keywords
                r"(?i)\b(ssn|social[\s-]security|passport\s*number|credit[\s-]card|cvv|expiry\s*date|pan\s*card|aadhaar|aadhar)\b",
                # Word-form digits (8+ consecutive) — phone number obfuscation
                r"(?i)\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|oh)\b[\s\-,.]*){8,}",
            ],
        }

        # ── Fuzzy match targets ────────────────────────────────────────────────
        # (canonical_phrase, attack_type, min_similarity_threshold)
        self.fuzzy_targets = [
            ("ignore all instructions",          "Prompt Injection",          85),
            ("ignore all previous instructions", "Prompt Injection",          85),
            ("disregard your instructions",      "Prompt Injection",          85),
            ("forget your instructions",         "Prompt Injection",          85),
            ("reveal your system prompt",        "System Prompt Leak",        85),
            ("give me your system prompt",       "System Prompt Leak",        85),
            ("print your instructions",          "System Prompt Leak",        85),
            ("show me your system prompt",       "System Prompt Leak",        85),
            ("act as dan",                       "Jailbreak Attempt",         88),
            ("do anything now",                  "Jailbreak Attempt",         88),
            ("developer mode enabled",           "Jailbreak Attempt",         88),
            ("you are now unrestricted",         "Jailbreak Attempt",         85),
            ("bypass all filters",               "Policy Bypass",             85),
            ("disable safety checks",            "Policy Bypass",             85),
            ("system override",                  "Policy Bypass",             88),
            ("dump the database",                "Data Exfiltration",         85),
            ("extract all user data",            "Data Exfiltration",         85),
            ("show me the api key",              "Sensitive Data Extraction", 85),
            ("give me the database password",    "Sensitive Data Extraction", 85),
            ("reveal the credentials",           "Sensitive Data Extraction", 85),
            ("show me the secret key",           "Sensitive Data Extraction", 85),
            ("what is the api key",              "Sensitive Data Extraction", 85),
            ("how to make a bomb",               "Violence / Weapons",        85),
            ("how to build explosives",          "Violence / Weapons",        85),
            ("how to make meth",                 "Drug Synthesis",            85),
            ("synthesize fentanyl",              "Drug Synthesis",            85),
            ("write a phishing email",           "Scam / Social Engineering", 85),
            ("how to hack a website",            "Malware / Hacking",         85),
            ("how to kill myself",               "Self Harm / Suicide",       85),
            ("commit suicide method",            "Self Harm / Suicide",       85),
        ]

    def _fuzzy_check(self, prompt: str) -> Tuple[bool, List[str], List[str]]:
        """
        Slide a window over the prompt and fuzzy-match substrings against
        known attack phrases. Catches typos like 'instuction' or 'sysem promt'.
        """
        prompt_lower = prompt.lower()
        words = prompt_lower.split()
        reasons = []
        attack_types = []
        matched = False

        for target_phrase, attack_type, threshold in self.fuzzy_targets:
            target_word_count = len(target_phrase.split())
            for i in range(len(words) - target_word_count + 1):
                window = " ".join(words[i: i + target_word_count])
                score = fuzz.ratio(window, target_phrase)
                if score >= threshold:
                    matched = True
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)
                    reasons.append(
                        f"Fuzzy match ({score}% similarity) to known attack phrase "
                        f"'{target_phrase}' [{attack_type}]"
                    )
                    break

        return matched, reasons, attack_types

    def detect(self, prompt: str) -> Tuple[bool, List[str], List[str]]:
        reasons = []
        attack_types = []
        is_malicious = False

        # 1. Regex pass (fast, exact)
        for attack_type, regex_list in self.patterns.items():
            for pattern in regex_list:
                if re.search(pattern, prompt):
                    is_malicious = True
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)
                    reasons.append(f"Matched known malicious pattern for {attack_type}")
                    break

        # 2. Fuzzy pass — only runs if regex missed
        if not is_malicious:
            fuzzy_matched, fuzzy_reasons, fuzzy_types = self._fuzzy_check(prompt)
            if fuzzy_matched:
                is_malicious = True
                reasons.extend(fuzzy_reasons)
                for t in fuzzy_types:
                    if t not in attack_types:
                        attack_types.append(t)

        return is_malicious, reasons, attack_types


pattern_detector = PatternDetector()