// The test counts the page and the README print about themselves.
//
// The KAT panel's note used to read: "The full suite (all 4 RFC 9382 vectors,
// the RFC 9383 vector, and the attack tests — 18 in total) runs under
// `npm test`". 18 is the known-answer tests plus the attack tests; it left out
// the 9 primitive-compatibility controls the README has always listed, so a
// sentence calling itself "the full suite" undercounted the suite by nine.
//
// A number a page prints about its own test suite cannot be checked by running
// the suite from inside it, so this checks the thing that actually went wrong:
// that the page's note and the README agree with each other, and that the total
// either of them claims is the sum of the parts it goes on to list.
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';

const kat = readFileSync(new URL('./kat.ts', import.meta.url), 'utf8');
const readme = readFileSync(new URL('../../README.md', import.meta.url), 'utf8');

it('the page note and the README agree, and each total is the sum of its parts', () => {
  const note = /text: 'These four run every page load\.(.*?)',\n/s.exec(kat)?.[1];
  expect(note, 'the KAT note is still where this test looks for it').toBeDefined();

  // No stale total may survive anywhere.
  expect(note).not.toContain('18 in total');
  expect(readme).not.toContain('**27 tests**');

  const parts = {
    knownAnswer: /(\d+) known-answer tests/.exec(note!)?.[1],
    attack: /(\d+) attack tests/.exec(note!)?.[1],
    controls: /(\d+) primitive-compatibility controls/.exec(note!)?.[1],
    audits: /(\d+) library-audit checks/.exec(note!)?.[1],
    meta: /(\d+) check that these counts are the real ones/.exec(note!)?.[1],
  };
  for (const [name, value] of Object.entries(parts)) {
    expect(value, `the note names a count for ${name}`).toBeDefined();
  }
  const sum = Object.values(parts).reduce((total, value) => total + Number(value), 0);

  const noteTotal = Number(/full suite is (\d+) tests/.exec(note!)?.[1]);
  expect(noteTotal, 'the note states a total').toBeGreaterThan(0);
  expect(noteTotal, 'the note total is the sum of the parts it lists').toBe(sum);

  // The README states the same total and the same breakdown.
  const readmeTotal = Number(/\*\*(\d+) tests\*\* \(Vitest\)/.exec(readme)?.[1]);
  expect(readmeTotal, 'the README total matches the page').toBe(noteTotal);
  const readmeParts =
    /— (\d+) known-answer \+ (\d+) attack \+ (\d+) primitive controls \+ (\d+) audit checks \+ (\d+) count check/.exec(
      readme,
    );
  expect(readmeParts, 'the README prints its breakdown').not.toBeNull();
  expect(readmeParts!.slice(1, 6)).toEqual([
    parts.knownAnswer,
    parts.attack,
    parts.controls,
    parts.audits,
    parts.meta,
  ]);

  // And the README's own prose bullets still carry the same three numbers, so a
  // change to one of them cannot pass by updating only the summary line.
  expect(readme).toContain(`**${parts.knownAnswer} known-answer tests**`);
  expect(readme).toContain(`**${parts.attack} attack tests**`);
  expect(readme).toContain(`**${parts.controls} primitive compatibility controls**`);
});
