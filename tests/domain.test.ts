import { describe, it, expect } from 'vitest';
import { cleanDomain } from '../src/domain.js';

describe('cleanDomain', () => {
  it('returns bare domain as-is', () => {
    expect(cleanDomain('example.com')).toBe('example.com');
  });

  it('extracts domain from email address', () => {
    expect(cleanDomain('user@example.com')).toBe('example.com');
  });

  it('extracts domain from HTTPS URL', () => {
    expect(cleanDomain('https://www.example.com/path?q=1')).toBe(
      'example.com'
    );
  });

  it('extracts domain from HTTP URL', () => {
    expect(cleanDomain('http://example.com/page')).toBe('example.com');
  });

  it('strips www prefix', () => {
    expect(cleanDomain('www.example.com')).toBe('example.com');
  });

  it('lowercases domain', () => {
    expect(cleanDomain('EXAMPLE.COM')).toBe('example.com');
  });

  it('removes trailing dot (FQDN)', () => {
    expect(cleanDomain('example.com.')).toBe('example.com');
  });

  it('trims whitespace', () => {
    expect(cleanDomain('  example.com  ')).toBe('example.com');
  });

  it('preserves subdomains (not www)', () => {
    expect(cleanDomain('sub.example.com')).toBe('sub.example.com');
  });

  it('handles email with uppercase and spaces', () => {
    expect(cleanDomain(' User@EXAMPLE.COM ')).toBe('example.com');
  });

  it('handles URL without path', () => {
    expect(cleanDomain('https://example.com')).toBe('example.com');
  });

  it('handles input with path but no protocol', () => {
    expect(cleanDomain('example.com/page')).toBe('example.com');
  });
});
