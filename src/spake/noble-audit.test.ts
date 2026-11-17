/* What "audited" covers for the Noble packages this lab ships.
 *
 * The README said the group and hash primitives "come from the audited
 * [`@noble/curves`] / `@noble/hashes`", and the page said P-256 runs "via the
 * audited @noble/curves group ops" — neither with a version. The two libraries
 * record different audits, both behind the pins here (^2.4.0 for each):
 *
 *   @noble/curves — "at version 2.3.0, in Aug 2026, by [Trail of Bits]"
 *   @noble/hashes — "at version 1.0.0, in Jan 2022, independently, by [Cure53]"
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\s+/g, ' ');

const pkg = JSON.parse(read('../../package.json'));
const curvesReadme = read('../../node_modules/@noble/curves/README.md');
const hashesReadme = read('../../node_modules/@noble/hashes/README.md');
const readmeSource = read('../../README.md');
const pageSource = read('../main.ts');

describe('the Noble audit claims', () => {
  it('pins versions later than either library has audited', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(pkg.dependencies['@noble/hashes']).toBe('^2.4.0');
    expect(curvesReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(hashesReadme).toMatch(/at version 1\.0\.0, in Jan 2022, independently, by \[Cure53\]/);
    expect(curvesReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
    expect(hashesReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('never calls the shipped packages simply "audited"', () => {
    for (const [name, text] of [
      ['README.md', flat(readmeSource)],
      ['src/main.ts', flat(pageSource)],
    ] as const) {
      expect(text, name).not.toContain('the audited [`@noble/curves`]');
      expect(text, name).not.toContain('the audited @noble/curves');
    }
  });

  it('names the audited version wherever the libraries are described', () => {
    expect(flat(readmeSource)).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
    expect(flat(readmeSource)).toContain('at version 1.0.0, in Jan 2022, independently, by [Cure53]');
    expect(flat(pageSource)).toContain('at version 2.3.0, in Aug 2026, by Trail of Bits');
    for (const text of [readmeSource, pageSource]) {
      expect(flat(text)).toMatch(/\^2\.4\.0/);
    }
  });
});
