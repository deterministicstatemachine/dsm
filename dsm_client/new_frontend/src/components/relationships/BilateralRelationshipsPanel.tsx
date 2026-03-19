/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useEffect, useState } from 'react';
import { dsmClient } from '../../services/dsmClient';

export default function BilateralRelationshipsPanel({ onNavigate }: { onNavigate?: (to: string) => void }) {
  const [contacts, setContacts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inspected, setInspected] = useState<any | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const res = await dsmClient.getContacts();
        setContacts(res?.contacts ?? []);
      } catch (e: any) {
        setError(e?.message || 'Failed to load contacts');
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, []);

  if (loading) return <div>Loading</div>;
  if (error) return <div>{error}</div>;

  if (contacts.length === 0) {
    return (
      <div>
        <h3>NO CONTACTS YET</h3>
        <p>Scan a contact&apos;s QR code to get started</p>
        <button onClick={() => onNavigate?.('qr')}>SCAN QR CODE</button>
        <button onClick={() => onNavigate?.('mycontact')}>MY QR</button>
      </div>
    );
  }

  return (
    <div>
      <div>
        {contacts.map((c: any, i: number) => (
          <div key={i}>{c.alias}</div>
        ))}
      </div>
      <button onClick={() => setInspected(contacts[0])}>INSPECT</button>
      {inspected && (
        <div>
          <h4>TRANSACTION HISTORY: {inspected.alias}</h4>
        </div>
      )}
    </div>
  );
}
