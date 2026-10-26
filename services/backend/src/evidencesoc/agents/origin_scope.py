"""Address scope and evidence-based verdict instructions for analysis."""

INTERNAL_SOURCE_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)

ORIGIN_SCOPE_INSTRUCTION = (
    "Derive origin.source_scope only from the cited observed_source_ip, never "
    "from attack intent or traffic direction. Use internal for addresses in "
    + ", ".join(INTERNAL_SOURCE_NETWORKS)
    + ". For other observed addresses use external only when "
    "ipaddress.ip_address(address).is_global is true; otherwise use unknown. "
    "When observed_source_ip is null or not established by cited evidence, use unknown. "
    "Apply the same rule to diagnosis.origin.source_scope. "
    "Origin attribution and ATT&CK technique mapping are separate from the verdict. "
    "Missing origin fields or a supported technique ID alone must not force an unknown verdict. "
    "Use benign only when the observed activity is positively explained by the supplied evidence as routine "
    "and no cited observation contradicts that explanation; this verdict is limited to the supplied activity. "
    "Absence of attack indicators alone does not establish benign. "
    "Keep unknown when competing explanations or missing behavioral evidence prevent a supported decision. "
)
