// CIS v3.0.0 5.1-5.3: "remote server administration ports" are 22 and 3389.
// A rule matches when its port range CONTAINS either, or when it is 0-0, the
// collector's value for protocol -1 (all traffic) which carries no range.
//
// One definition for the compliance controls and RULE-002. RULE-002 had its
// own copy that matched port_from alone: it missed 20-25, which contains 22,
// and flagged 0-21, which contains neither.
export const ADMIN_PORT_RANGE_PREDICATE = `or(
            has('port_from', 0).has('port_to', 0),
            has('port_from', lte(22)).has('port_to', gte(22)),
            has('port_from', lte(3389)).has('port_to', gte(3389))
          )`;
