// IAM-style wildcard match: * is any run, ? one character, ignoring case.
// Iterative rather than a generated regex: policy text is written by anyone
// with IAM access, and a pattern like `*a*a*a*a*b` made a regex backtrack
// exponentially. This is at most pattern length × text length steps.
export function globMatch(pattern: string, text: string): boolean {
  const p = pattern.toLowerCase();
  const s = text.toLowerCase();
  let pi = 0;
  let si = 0;
  let star = -1;
  let resume = 0;
  while (si < s.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === s[si])) {
      pi++;
      si++;
    } else if (pi < p.length && p[pi] === '*') {
      star = pi++;
      resume = si;
    } else if (star !== -1) {
      pi = star + 1;
      si = ++resume;
    } else {
      return false;
    }
  }
  while (p[pi] === '*') pi++;
  return pi === p.length;
}
