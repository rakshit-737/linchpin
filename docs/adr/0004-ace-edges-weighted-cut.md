# ADR 0004: AD ACE edges and an effort-weighted min cut

**Status:** accepted (v1.0)

## Context
v0.2 modelled only AdminTo, sessions and Domain-Admin membership from BloodHound. Real AD compromise often goes
through ACL abuse (GenericAll on a user, AddMember on a group, DCSync rights on the domain), and the fix for it is
"remove the ACE", which neither patching nor credential rotation covers. The v0.2 min cut also counted every
remediation as one unit, although a segmentation change costs far more effort than a patch.

## Decision
* New node label `Ace` (id `ace:<principal>-><target>`) with edges `Credential -HAS_ACE-> Ace -ABUSES-> X`,
  where X is the controlled user's `Credential`, `Privilege` on hosts the controlled group or computer administers,
  or the NTDS `DataStore` for DCSync (GetChanges + GetChangesAll) and full domain control. `ABUSES` uses a new skill
  class `acl_abuse` (0.25). `Ace` is a remediable candidate with the action "remove <rights> of <principal> on
  <target>". The change is additive to the frozen contracts (v1.2).
* ACEs held by principals that are already Domain / Enterprise / BUILTIN Administrators are dropped, since they add no
  new capability and would only add noise.
* `min_remediation_cut(weighted=True)` sets vertex capacities to `cfg.fix_cost[label]`, default Vuln = Credential =
  Ace = 1 and Host (segmentation) = 3, and returns the minimum-*effort* cut. The unweighted cut stays the default
  for the optimizer, so the benchmark semantics are unchanged.

## Consequences
On the real `TESTLAB.LOCAL` collection, 3 abusable ACEs survive the filter (GenericAll and RBCD on computers, and
a direct DCSync user). None of them is reachable from the declared entry points, so the case-study plan is
unchanged. ADCS (ESC1-8), shadow credentials, GPO links and trusts are still not modelled. The effort weights are
defaults, not measured costs.
