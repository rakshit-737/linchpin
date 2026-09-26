# Graph model (FROZEN)

Node ids are prefixed by label so they are globally unique:

| Label | id form | props |
| --- | --- | --- |
| Internet (virtual) | `internet` | the attacker's starting point |
| Host | `host:<host_id>` | os, segment, is_entrypoint, is_crown_jewel |
| Service | `svc:<host_id>:<port>` | port, proto, software, version |
| Vuln | `vuln:<cve>@<host_id>:<port>` | cve, cvss_base, epss, exploit_maturity |
| Credential | `cred:<principal>` | principal, cred_type |
| Privilege | `priv:admin@<host_id>` | principal, level |
| DataStore | `ds:<name>` | sensitivity |
| Ace (v1.2, additive) | `ace:<principal>-><target>` | principal, target, target_kind, rights |

Attack edges are stored **in attacker-traversal direction** (a path is a walk the attacker takes):

| Rel | From -> To | Meaning / stage |
| --- | --- | --- |
| `CAN_REACH` | Host/Internet -> Service | network reachability to an exposed service (lateral / recon) |
| `HAS_VULN` | Service -> Vuln | service is vulnerable (exploit) |
| `ENABLES` | Vuln -> Privilege | exploiting yields privilege (exploit) |
| `LEADS_TO` | Privilege -> Host | privilege gives control of host (privesc) |
| `STORED_ON` | Host -> Credential | cred recoverable from a controlled host (privesc); stored reversed vs. spec text |
| `GRANTS` | Credential -> Privilege | using cred yields privilege on a host it is VALID_ON (lateral) |
| `HOLDS` | Host -> DataStore | crown-jewel data on host (objective); stored reversed vs. spec text |
| `HAS_ACE` (v1.2) | Credential -> Ace | principal holds an abusable AD ACL entry (lateral) |
| `ABUSES` (v1.2) | Ace -> Credential / Privilege / DataStore | abusing the ACE yields a user, local admin, or DCSync of the NTDS (privesc, class `acl_abuse`) |

Deviation from the original spec draft: `CAN_REACH` terminates on the target's *Service* (not the Host)
so that simple paths never revisit a host, and `RUNS` / `VALID_ON` are kept as node attributes
rather than traversal edges. Edge id = `"<src>|<REL>|<dst>"`.
