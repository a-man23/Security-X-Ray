"""
Domain classification rules for Security X-Ray.
Maps registered domains to categories and known providers.
"""
 
# Known third-party domain patterns
# Structure: { registrable_domain: { "category": ..., "provider": ... } }
 
KNOWN_DOMAINS: dict[str, dict] = {
    # Analytics
    "google-analytics.com":    {"category": "analytics",  "provider": "Google Analytics"},
    "googletagmanager.com":    {"category": "analytics",  "provider": "Google Tag Manager"},
    "googletagservices.com":   {"category": "analytics",  "provider": "Google Tag Services"},
    "analytics.google.com":    {"category": "analytics",  "provider": "Google Analytics"},
    "segment.com":             {"category": "analytics",  "provider": "Segment"},
    "segment.io":              {"category": "analytics",  "provider": "Segment"},
    "mixpanel.com":            {"category": "analytics",  "provider": "Mixpanel"},
    "amplitude.com":           {"category": "analytics",  "provider": "Amplitude"},
    "heap.io":                 {"category": "analytics",  "provider": "Heap"},
    "hotjar.com":              {"category": "analytics",  "provider": "Hotjar"},
    "mouseflow.com":           {"category": "analytics",  "provider": "Mouseflow"},
    "fullstory.com":           {"category": "analytics",  "provider": "FullStory"},
    "logrocket.com":           {"category": "analytics",  "provider": "LogRocket"},
    "newrelic.com":            {"category": "analytics",  "provider": "New Relic"},
    "nr-data.net":             {"category": "analytics",  "provider": "New Relic"},
    "datadoghq.com":           {"category": "analytics",  "provider": "Datadog"},
    "clarity.ms":              {"category": "analytics",  "provider": "Microsoft Clarity"},
    "quantserve.com":          {"category": "analytics",  "provider": "Quantcast"},
    "mxpnl.com":               {"category": "analytics",  "provider": "Mixpanel"},
 
    # Advertising
    "doubleclick.net":         {"category": "advertising", "provider": "Google DoubleClick"},
    "googlesyndication.com":   {"category": "advertising", "provider": "Google AdSense"},
    "googleadservices.com":    {"category": "advertising", "provider": "Google Ads"},
    "google.com":              {"category": "advertising", "provider": "Google"},  # ads/tracking subdomains
    "facebook.com":            {"category": "advertising", "provider": "Meta"},
    "facebook.net":            {"category": "advertising", "provider": "Meta Pixel"},
    "connect.facebook.net":    {"category": "advertising", "provider": "Meta Pixel"},
    "ads-twitter.com":         {"category": "advertising", "provider": "Twitter Ads"},
    "static.ads-twitter.com":  {"category": "advertising", "provider": "Twitter Ads"},
    "amazon-adsystem.com":     {"category": "advertising", "provider": "Amazon Ads"},
    "adnxs.com":               {"category": "advertising", "provider": "AppNexus/Xandr"},
    "rubiconproject.com":      {"category": "advertising", "provider": "Magnite/Rubicon"},
    "pubmatic.com":            {"category": "advertising", "provider": "PubMatic"},
    "openx.net":               {"category": "advertising", "provider": "OpenX"},
    "criteo.com":              {"category": "advertising", "provider": "Criteo"},
    "criteo.net":              {"category": "advertising", "provider": "Criteo"},
    "outbrain.com":            {"category": "advertising", "provider": "Outbrain"},
    "taboola.com":             {"category": "advertising", "provider": "Taboola"},
    "moatads.com":             {"category": "advertising", "provider": "Oracle Moat"},
    "adsrvr.org":              {"category": "advertising", "provider": "The Trade Desk"},
    "casalemedia.com":         {"category": "advertising", "provider": "Index Exchange"},
    "indexww.com":             {"category": "advertising", "provider": "Index Exchange"},
    "smartadserver.com":       {"category": "advertising", "provider": "Smart AdServer"},
    "bidswitch.net":           {"category": "advertising", "provider": "Bidswitch"},
    "yahoo.com":               {"category": "advertising", "provider": "Yahoo Ads"},
    "yimg.com":                {"category": "advertising", "provider": "Yahoo"},
    "demdex.net":              {"category": "advertising", "provider": "Adobe Audience Manager"},
    "everesttech.net":         {"category": "advertising", "provider": "Adobe Advertising"},
    "tiqcdn.com":              {"category": "advertising", "provider": "Tealium"},
    "snap.licdn.com":          {"category": "advertising", "provider": "LinkedIn Ads"},
    "ads.linkedin.com":        {"category": "advertising", "provider": "LinkedIn Ads"},
    "snapchat.com":            {"category": "advertising", "provider": "Snapchat Ads"},
 
    # CDN / Javascript
    "cloudflare.com":          {"category": "cdn",         "provider": "Cloudflare"},
    "cdnjs.cloudflare.com":    {"category": "cdn",         "provider": "Cloudflare CDNJS"},
    "jsdelivr.net":            {"category": "cdn",         "provider": "jsDelivr"},
    "unpkg.com":               {"category": "cdn",         "provider": "unpkg"},
    "bootstrapcdn.com":        {"category": "cdn",         "provider": "BootstrapCDN"},
    "maxcdn.bootstrapcdn.com": {"category": "cdn",         "provider": "BootstrapCDN"},
    "jquery.com":              {"category": "cdn",         "provider": "jQuery CDN"},
    "code.jquery.com":         {"category": "cdn",         "provider": "jQuery CDN"},
    "ajax.googleapis.com":     {"category": "cdn",         "provider": "Google Hosted Libraries"},
    "ajax.aspnetcdn.com":      {"category": "cdn",         "provider": "Microsoft Ajax CDN"},
    "stackpath.bootstrapcdn.com": {"category": "cdn",      "provider": "StackPath CDN"},
    "fastly.net":              {"category": "cdn",         "provider": "Fastly"},
    "akamaihd.net":            {"category": "cdn",         "provider": "Akamai"},
    "akamai.net":              {"category": "cdn",         "provider": "Akamai"},
    "cloudfront.net":          {"category": "cdn",         "provider": "Amazon CloudFront"},
    "azureedge.net":           {"category": "cdn",         "provider": "Azure CDN"},
    "windows.net":             {"category": "cdn",         "provider": "Azure Blob/CDN"},
    "amazonaws.com":           {"category": "cdn",         "provider": "Amazon S3/CloudFront"},
    "gstatic.com":             {"category": "cdn",         "provider": "Google Static CDN"},
    "googleusercontent.com":   {"category": "cdn",         "provider": "Google User Content"},
 
    # Socail
    "twitter.com":             {"category": "social",      "provider": "Twitter/X"},
    "x.com":                   {"category": "social",      "provider": "Twitter/X"},
    "platform.twitter.com":    {"category": "social",      "provider": "Twitter Widget"},
    "instagram.com":           {"category": "social",      "provider": "Instagram"},
    "linkedin.com":            {"category": "social",      "provider": "LinkedIn"},
    "pinterest.com":           {"category": "social",      "provider": "Pinterest"},
    "tiktok.com":              {"category": "social",      "provider": "TikTok"},
    "youtube.com":             {"category": "social",      "provider": "YouTube"},
    "ytimg.com":               {"category": "social",      "provider": "YouTube"},
    "reddit.com":              {"category": "social",      "provider": "Reddit"},
    "disqus.com":              {"category": "social",      "provider": "Disqus"},
    "disquscdn.com":           {"category": "social",      "provider": "Disqus CDN"},
    "addthis.com":             {"category": "social",      "provider": "AddThis"},
    "sharethis.com":           {"category": "social",      "provider": "ShareThis"},
 
    # Customer Support
    "intercom.io":             {"category": "support",     "provider": "Intercom"},
    "intercom.com":            {"category": "support",     "provider": "Intercom"},
    "intercomcdn.com":         {"category": "support",     "provider": "Intercom CDN"},
    "zendesk.com":             {"category": "support",     "provider": "Zendesk"},
    "zdassets.com":            {"category": "support",     "provider": "Zendesk Assets"},
    "freshdesk.com":           {"category": "support",     "provider": "Freshdesk"},
    "tawk.to":                 {"category": "support",     "provider": "Tawk.to"},
    "crisp.chat":              {"category": "support",     "provider": "Crisp Chat"},
    "livechatinc.com":         {"category": "support",     "provider": "LiveChat"},
    "hubspot.com":             {"category": "support",     "provider": "HubSpot"},
    "hs-scripts.com":          {"category": "support",     "provider": "HubSpot"},
    "hs-analytics.net":        {"category": "support",     "provider": "HubSpot Analytics"},
    "hsforms.com":             {"category": "support",     "provider": "HubSpot Forms"},
    "drift.com":               {"category": "support",     "provider": "Drift"},
    "driftt.com":              {"category": "support",     "provider": "Drift"},
 
    # A/B testing
    "optimizely.com":          {"category": "ab_testing",  "provider": "Optimizely"},
    "cdn.optimizely.com":      {"category": "ab_testing",  "provider": "Optimizely"},
    "launchdarkly.com":        {"category": "ab_testing",  "provider": "LaunchDarkly"},
    "split.io":                {"category": "ab_testing",  "provider": "Split.io"},
    "vwo.com":                 {"category": "ab_testing",  "provider": "VWO"},
    "visualwebsiteoptimizer.com": {"category": "ab_testing", "provider": "VWO"},
    "kameleoon.com":           {"category": "ab_testing",  "provider": "Kameleoon"},
 
    # Tag managers
    "tealiumiq.com":           {"category": "tag_manager", "provider": "Tealium IQ"},
    "ensighten.com":           {"category": "tag_manager", "provider": "Ensighten"},
    "qubit.com":               {"category": "tag_manager", "provider": "Qubit"},
    "tagcommander.com":        {"category": "tag_manager", "provider": "TagCommander"},
 
    # Security
    "recaptcha.net":           {"category": "security",    "provider": "Google reCAPTCHA"},
    "hcaptcha.com":            {"category": "security",    "provider": "hCaptcha"},
    "akismet.com":             {"category": "security",    "provider": "Akismet"},
    "sentry.io":               {"category": "security",    "provider": "Sentry"},
    "browser.sentry-cdn.com":  {"category": "security",    "provider": "Sentry CDN"},
    "bugsnag.com":             {"category": "security",    "provider": "Bugsnag"},
 
    # Payment
    "stripe.com":              {"category": "payments",    "provider": "Stripe"},
    "js.stripe.com":           {"category": "payments",    "provider": "Stripe JS"},
    "paypal.com":              {"category": "payments",    "provider": "PayPal"},
    "paypalobjects.com":       {"category": "payments",    "provider": "PayPal Objects"},
    "braintreegateway.com":    {"category": "payments",    "provider": "Braintree"},
    "square.com":              {"category": "payments",    "provider": "Square"},
 
    # UI/Fonts
    "fonts.googleapis.com":    {"category": "fonts",       "provider": "Google Fonts"},
    "fonts.gstatic.com":       {"category": "fonts",       "provider": "Google Fonts"},
    "use.typekit.net":         {"category": "fonts",       "provider": "Adobe Fonts (Typekit)"},
    "use.fontawesome.com":     {"category": "fonts",       "provider": "Font Awesome"},
    "kit.fontawesome.com":     {"category": "fonts",       "provider": "Font Awesome Kit"},
}
 
# Heuristic keyword patterns (fallback)
# If isn't in KNOWN_DOMAINS. Checked in order.
HEURISTIC_PATTERNS: list[dict] = [
    {"keywords": ["analytics", "tracking", "tracker", "telemetry", "metric", "stat", "insight", "beacon"],
     "category": "analytics",  "provider": None},
    {"keywords": ["ads", "adserver", "adtech", "advert", "ad-", "-ad.", "banner", "bidder", "dsp", "ssp", "rtb"],
     "category": "advertising", "provider": None},
    {"keywords": ["cdn", "static", "assets", "cache", "edge", "delivery", "content"],
     "category": "cdn",         "provider": None},
    {"keywords": ["social", "share", "like", "follow", "tweet", "facebook", "instagram", "linkedin", "tiktok"],
     "category": "social",      "provider": None},
    {"keywords": ["chat", "support", "helpdesk", "crm", "intercom", "zendesk", "livechat"],
     "category": "support",     "provider": None},
    {"keywords": ["captcha", "recaptcha", "hcaptcha", "sentry", "bugsnag", "error", "waf"],
     "category": "security",    "provider": None},
    {"keywords": ["payment", "pay", "stripe", "checkout", "billing"],
     "category": "payments",    "provider": None},
    {"keywords": ["font", "typeface", "icon", "svg", "webfont"],
     "category": "fonts",       "provider": None},
    {"keywords": ["test", "experiment", "optimize", "variant", "abtesting", "split"],
     "category": "ab_testing",  "provider": None},
    {"keywords": ["tag", "tagmanager", "tms", "container", "ensighten"],
     "category": "tag_manager", "provider": None},
]
 
VALID_CATEGORIES = {
    "analytics", "advertising", "cdn", "social", "support",
    "ab_testing", "tag_manager", "security", "payments", "fonts", "unknown"
}
 
 
def classify_domain(registrable_domain: str) -> dict:
    """
    Return {"category": str, "provider": str | None} for a registrable domain.
    Checks the known-domain table first, then keyword heuristics.
    """
    d = registrable_domain.lower()
 
    # 1. Exact match in known table
    if d in KNOWN_DOMAINS:
        return KNOWN_DOMAINS[d]
 
    # 2. Suffix / subdomain match :  "cdn.segment.io" → "segment.io"
    for known, meta in KNOWN_DOMAINS.items():
        if d.endswith("." + known) or d == known:
            return meta
 
    # 3. Heuristic keyword scan
    for rule in HEURISTIC_PATTERNS:
        if any(kw in d for kw in rule["keywords"]):
            return {"category": rule["category"], "provider": rule["provider"]}
 
    return {"category": "unknown", "provider": None}