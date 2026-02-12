import { describe, it, expect } from 'vitest';
import { parseDmarc } from '../src/parse-dmarc.js';

describe('parseDmarc', () => {
  it('parses a minimal record', () => {
    const result = parseDmarc('v=DMARC1; p=none');
    expect(result).toEqual({ p: 'none' });
  });

  it('parses a full record with all tags', () => {
    const raw =
      'v=DMARC1; p=reject; sp=quarantine; aspf=s; adkim=s; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=50';
    const result = parseDmarc(raw);
    expect(result).toEqual({
      p: 'reject',
      sp: 'quarantine',
      aspf: 's',
      adkim: 's',
      rua: ['dmarc@example.com'],
      ruf: ['forensics@example.com'],
      pct: 50,
    });
  });

  it('returns null for non-DMARC records', () => {
    expect(parseDmarc('v=spf1 include:example.com ~all')).toBeNull();
    expect(parseDmarc('some random text')).toBeNull();
    expect(parseDmarc('')).toBeNull();
  });

  it('handles p=reject', () => {
    const result = parseDmarc('v=DMARC1; p=reject');
    expect(result).toEqual({ p: 'reject' });
  });

  it('handles p=quarantine', () => {
    const result = parseDmarc('v=DMARC1; p=quarantine');
    expect(result).toEqual({ p: 'quarantine' });
  });

  it('handles p=none', () => {
    const result = parseDmarc('v=DMARC1; p=none');
    expect(result).toEqual({ p: 'none' });
  });

  it('returns null when p tag is missing', () => {
    expect(parseDmarc('v=DMARC1; rua=mailto:a@b.com')).toBeNull();
  });

  it('parses rua with multiple mailto URIs', () => {
    const raw =
      'v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com';
    const result = parseDmarc(raw);
    expect(result?.rua).toEqual(['a@example.com', 'b@example.com']);
  });

  it('parses ruf with multiple mailto URIs', () => {
    const raw =
      'v=DMARC1; p=none; ruf=mailto:x@example.com,mailto:y@example.com';
    const result = parseDmarc(raw);
    expect(result?.ruf).toEqual(['x@example.com', 'y@example.com']);
  });

  it('handles whitespace variations', () => {
    const raw = 'v=DMARC1;p=reject;  sp=none ;aspf=r';
    const result = parseDmarc(raw);
    expect(result).toEqual({
      p: 'reject',
      sp: 'none',
      aspf: 'r',
    });
  });

  it('handles leading/trailing whitespace in the record', () => {
    const result = parseDmarc('  v=DMARC1; p=none  ');
    expect(result).toEqual({ p: 'none' });
  });

  it('parses aspf=s and adkim=s', () => {
    const result = parseDmarc('v=DMARC1; p=none; aspf=s; adkim=s');
    expect(result?.aspf).toBe('s');
    expect(result?.adkim).toBe('s');
  });

  it('parses aspf=r and adkim=r', () => {
    const result = parseDmarc('v=DMARC1; p=none; aspf=r; adkim=r');
    expect(result?.aspf).toBe('r');
    expect(result?.adkim).toBe('r');
  });

  it('parses pct=50', () => {
    const result = parseDmarc('v=DMARC1; p=quarantine; pct=50');
    expect(result?.pct).toBe(50);
  });

  it('parses pct=100', () => {
    const result = parseDmarc('v=DMARC1; p=reject; pct=100');
    expect(result?.pct).toBe(100);
  });

  it('parses the Rule.io default DMARC record', () => {
    const raw =
      'v=DMARC1; p=none; rua=mailto:dmarc@rule.se; ruf=mailto:authfail@rule.se';
    const result = parseDmarc(raw);
    expect(result).toEqual({
      p: 'none',
      rua: ['dmarc@rule.se'],
      ruf: ['authfail@rule.se'],
    });
  });

  // Edge cases from Copilot review

  it('handles case-insensitive policy values', () => {
    expect(parseDmarc('v=DMARC1; p=REJECT')).toEqual({ p: 'reject' });
    expect(parseDmarc('v=DMARC1; p=Quarantine')).toEqual({
      p: 'quarantine',
    });
    expect(parseDmarc('v=DMARC1; p=NONE')).toEqual({ p: 'none' });
  });

  it('handles case-insensitive sp values', () => {
    const result = parseDmarc('v=DMARC1; p=none; sp=REJECT');
    expect(result?.sp).toBe('reject');
  });

  it('handles case-insensitive alignment modes', () => {
    const result = parseDmarc('v=DMARC1; p=none; aspf=S; adkim=R');
    expect(result?.aspf).toBe('s');
    expect(result?.adkim).toBe('r');
  });

  it('ignores non-mailto URIs in rua', () => {
    const result = parseDmarc(
      'v=DMARC1; p=none; rua=http://example.com'
    );
    expect(result?.rua).toBeUndefined();
  });

  it('ignores non-mailto URIs in ruf', () => {
    const result = parseDmarc(
      'v=DMARC1; p=none; ruf=https://example.com'
    );
    expect(result?.ruf).toBeUndefined();
  });

  it('filters non-mailto URIs but keeps valid ones', () => {
    const result = parseDmarc(
      'v=DMARC1; p=none; rua=http://bad.com,mailto:good@example.com'
    );
    expect(result?.rua).toEqual(['good@example.com']);
  });

  it('ignores invalid pct values (non-numeric)', () => {
    const result = parseDmarc('v=DMARC1; p=none; pct=abc');
    expect(result?.pct).toBeUndefined();
  });

  it('ignores pct values below 0', () => {
    const result = parseDmarc('v=DMARC1; p=none; pct=-10');
    expect(result?.pct).toBeUndefined();
  });

  it('ignores pct values above 100', () => {
    const result = parseDmarc('v=DMARC1; p=none; pct=150');
    expect(result?.pct).toBeUndefined();
  });

  it('accepts pct=0', () => {
    const result = parseDmarc('v=DMARC1; p=none; pct=0');
    expect(result?.pct).toBe(0);
  });

  it('uses last value when duplicate tags exist', () => {
    const result = parseDmarc('v=DMARC1; p=none; p=reject');
    expect(result?.p).toBe('reject');
  });
});
