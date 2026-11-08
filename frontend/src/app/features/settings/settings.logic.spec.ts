import { describeCron, randomSecret } from './settings.logic';

describe('settings logic', () => {
  it('reads common cron expressions in French', () => {
    expect(describeCron('0 2 * * *')).toBe('chaque jour à 2 h');
    expect(describeCron('0 0 6 * * MON-FRI')).toBe('du lundi au vendredi à 6 h');
    expect(describeCron('30 7 * * 1')).toBe('chaque lundi à 7 h 30');
    expect(describeCron('0 3 1 * *')).toBe('le 1er de chaque mois à 3 h');
    expect(describeCron('*/30 * * * *')).toBe('*/30 * * * *');
    expect(describeCron('@daily')).toBe('@daily');
  });

  it('generates hexadecimal secrets', () => {
    const s = randomSecret();
    expect(s.length).toBe(48);
    expect(/^[0-9a-f]+$/.test(s)).toBe(true);
    expect(randomSecret()).not.toBe(s);
  });
});
