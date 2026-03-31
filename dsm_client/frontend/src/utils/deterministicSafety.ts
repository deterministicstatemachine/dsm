import { bridgeEvents } from '../bridge/bridgeEvents';

export type DeterministicSafetyDetail = {
  classification: string;
  message: string;
};

const SAFETY_REGEX = /Deterministic safety rejection \[([^\]]+)\]:\s*(.*)/i;

export function parseDeterministicSafety(message?: string | null): DeterministicSafetyDetail | null {
  if (!message) return null;
  const match = String(message).match(SAFETY_REGEX);
  if (!match) return null;
  const classification = String(match[1] || '').trim();
  const detail = String(match[2] || '').trim();
  if (!classification) return null;
  return { classification, message: detail };
}

export function emitDeterministicSafetyIfPresent(message?: string | null): boolean {
  const detail = parseDeterministicSafety(message);
  if (!detail) return false;
  try {
    bridgeEvents.emit('dsm.deterministicSafety', detail);
  } catch {
    // ignore
  }
  return true;
}
