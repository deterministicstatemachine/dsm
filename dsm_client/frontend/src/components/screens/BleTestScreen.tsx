/* eslint-disable @typescript-eslint/no-explicit-any */
// Developer-only BLE transfer test screen.
// Accessed via Settings > Dev Mode > BLE TRANSFER TEST.

import React, { useState, useCallback, useRef } from 'react';
import {
  BleRole,
  BleStep,
  BleStepResult,
  getSteps,
  runBleInteractiveStep,
} from '../../vectors/bleInteractiveVectors';
import { useDpadNav } from '../../hooks/useDpadNav';

interface BleTestScreenProps {
  onNavigate?: (screen: string) => void;
}

interface LogEntry {
  time: string;
  step: string;
  status: string;
  success: boolean;
}

export default function BleTestScreen({ onNavigate }: BleTestScreenProps): JSX.Element {
  const [role, setRole] = useState<BleRole>('sender');
  const [completedStep, setCompletedStep] = useState(-1);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  const steps = getSteps(role);

  const appendLog = useCallback((entry: LogEntry) => {
    setLog(prev => [...prev, entry]);
    setTimeout(() => {
      logRef.current?.scrollTo(0, logRef.current.scrollHeight);
    }, 50);
  }, []);

  const handleStep = useCallback(async (step: BleStep, idx: number) => {
    setRunning(true);
    const now = new Date().toLocaleTimeString();
    appendLog({ time: now, step, status: 'Running...', success: true });

    const result: BleStepResult = await runBleInteractiveStep(role, step);
    appendLog({ time: now, step, status: result.status, success: result.success });

    if (result.success) {
      setCompletedStep(idx);
    }
    setRunning(false);
  }, [role, appendLog]);

  const handleRoleSwitch = useCallback((newRole: BleRole) => {
    setRole(newRole);
    setCompletedStep(-1);
    setLog([]);
  }, []);

  // --- D-pad navigation ---
  // Items: BACK (0), SENDER (1), RECEIVER (2), then step buttons (3..3+steps.length-1)
  const itemCount = 3 + steps.length;
  const onSelect = useCallback((idx: number) => {
    if (idx === 0) {
      onNavigate?.('settings');
      return;
    }
    if (idx === 1) {
      handleRoleSwitch('sender');
      return;
    }
    if (idx === 2) {
      handleRoleSwitch('receiver');
      return;
    }

    const stepIdx = idx - 3;
    const step = steps[stepIdx];
    const enabled = !running && stepIdx <= completedStep + 1;
    if (step && enabled) {
      void handleStep(step, stepIdx);
    }
  }, [onNavigate, handleRoleSwitch, steps, running, completedStep, handleStep]);

  const { focusedIndex } = useDpadNav({
    itemCount,
    onSelect,
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <div style={{
      padding: 16,
      fontFamily: "'Martian Mono', monospace",
      color: 'var(--text-dark)',
      background: 'var(--bg)',
      minHeight: '100%',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ fontSize: 14, margin: 0 }}>BLE TRANSFER TEST</h2>
        <button
          className={`settings-action-btn${fc(0)}`}
          style={{ fontSize: 8, padding: '4px 8px' }}
          onClick={() => onNavigate?.('settings')}
        >
          BACK
        </button>
      </div>

      {/* Role selector */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button
          className={`settings-action-btn${fc(1)}`}
          style={{
            fontSize: 10,
            flex: 1,
            padding: '8px 4px',
            opacity: role === 'sender' ? 1 : 0.5,
            border: role === 'sender' ? '2px solid var(--text-dark)' : '1px solid var(--border)',
          }}
          onClick={() => handleRoleSwitch('sender')}
        >
          SENDER
        </button>
        <button
          className={`settings-action-btn${fc(2)}`}
          style={{
            fontSize: 10,
            flex: 1,
            padding: '8px 4px',
            opacity: role === 'receiver' ? 1 : 0.5,
            border: role === 'receiver' ? '2px solid var(--text-dark)' : '1px solid var(--border)',
          }}
          onClick={() => handleRoleSwitch('receiver')}
        >
          RECEIVER
        </button>
      </div>

      {/* Step buttons */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
        {steps.map((step, idx) => {
          const enabled = !running && idx <= completedStep + 1;
          const done = idx <= completedStep;
          return (
            <button
              key={step}
              className={`settings-action-btn${fc(idx + 3)}`}
              disabled={!enabled}
              style={{
                fontSize: 9,
                padding: '8px 12px',
                textAlign: 'left',
                opacity: enabled ? 1 : 0.4,
                background: done ? 'rgba(0,180,0,0.1)' : undefined,
              }}
              onClick={() => handleStep(step, idx)}
            >
              {done ? '[OK] ' : `[${idx + 1}] `}
              {step.toUpperCase()}
            </button>
          );
        })}
      </div>

      {/* Log area */}
      <div style={{ fontSize: 10, fontWeight: 'bold', marginBottom: 4 }}>LOG</div>
      <div
        ref={logRef}
        style={{
          height: 200,
          overflow: 'auto',
          border: '1px solid var(--border)',
          padding: 8,
          fontSize: 8,
          lineHeight: 1.5,
          fontFamily: 'monospace',
          background: 'rgba(var(--text-rgb),0.05)',
        }}
      >
        {log.length === 0 && (
          <div style={{ opacity: 0.5 }}>Select a role and run steps sequentially.</div>
        )}
        {log.map((entry, i) => (
          <div key={i} style={{ color: 'var(--text-dark)', opacity: entry.success ? 1 : 0.7, textDecoration: entry.success ? 'none' : 'line-through' }}>
            [{entry.time}] {entry.step}: {entry.status}
          </div>
        ))}
      </div>
    </div>
  );
}
