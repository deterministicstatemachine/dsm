import React from 'react';
import fs from 'fs';
import path from 'path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';

const mockNav = { currentScreen: 'home' as string };

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    setPreference: jest.fn().mockResolvedValue(undefined),
    getPreference: jest.fn().mockResolvedValue(null),
  },
}));
jest.mock('../../../stores/walletStore', () => ({
  walletStore: { refreshAll: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('../../../stores/contactsStore', () => ({
  contactsStore: { refreshContacts: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('../practiceMode', () => ({
  practiceMode: { enter: jest.fn(), leave: jest.fn() },
}));
jest.mock('../../../runtime/navigationStore', () => ({
  navigationStore: {
    navigate: jest.fn(),
    getSnapshot: () => ({ currentScreen: mockNav.currentScreen }),
  },
  useNavigationStore: () => ({ currentScreen: mockNav.currentScreen }),
}));

import { dsmClient } from '../../../services/dsmClient';
import { walletStore } from '../../../stores/walletStore';
import { navigationStore } from '../../../runtime/navigationStore';
import { practiceMode } from '../practiceMode';
import { TOUR_STEPS } from '../tourSteps';
import { TOUR_SEEN_PREF, hasSeenTour, tourStore } from '../tourStore';
import TourOffer from '../TourOffer';
import { placeDialog } from '../GuidedTour';

const client = dsmClient as unknown as { setPreference: jest.Mock; getPreference: jest.Mock };

function resetTour(): void {
  if (tourStore.getSnapshot().active) tourStore.end();
  jest.clearAllMocks();
  client.getPreference.mockResolvedValue(null);
  client.setPreference.mockResolvedValue(undefined);
  mockNav.currentScreen = 'home';
}

describe('tourStore', () => {
  beforeEach(resetTour);

  it('starting enters practice mode, reloads the stores and opens step one', () => {
    tourStore.start();
    expect(practiceMode.enter).toHaveBeenCalledTimes(1);
    expect(walletStore.refreshAll).toHaveBeenCalled();
    expect(tourStore.getSnapshot()).toEqual({ active: true, index: 0 });
  });

  it('starting twice does not enter practice mode twice', () => {
    tourStore.start();
    tourStore.start();
    expect(practiceMode.enter).toHaveBeenCalledTimes(1);
  });

  it('next and back move one step and back stops at the first step', () => {
    tourStore.start();
    tourStore.back();
    expect(tourStore.getSnapshot().index).toBe(0);
    tourStore.next();
    tourStore.next();
    expect(tourStore.getSnapshot().index).toBe(2);
    tourStore.back();
    expect(tourStore.getSnapshot().index).toBe(1);
  });

  it('next on the last step ends the tour', () => {
    tourStore.start();
    for (let i = 0; i < TOUR_STEPS.length - 1; i += 1) tourStore.next();
    expect(tourStore.getSnapshot().index).toBe(TOUR_STEPS.length - 1);
    tourStore.next();
    expect(tourStore.getSnapshot().active).toBe(false);
    expect(practiceMode.leave).toHaveBeenCalledTimes(1);
  });

  it('ending leaves practice mode, returns home and remembers the tour was seen', () => {
    tourStore.start();
    tourStore.end();
    expect(practiceMode.leave).toHaveBeenCalledTimes(1);
    expect(navigationStore.navigate).toHaveBeenCalledWith('home');
    expect(client.setPreference).toHaveBeenCalledWith(TOUR_SEEN_PREF, 'true');
    expect(tourStore.getSnapshot()).toEqual({ active: false, index: 0 });
  });

  it('ending when not running does nothing', () => {
    tourStore.end();
    expect(practiceMode.leave).not.toHaveBeenCalled();
    expect(client.setPreference).not.toHaveBeenCalled();
  });
});

describe('hasSeenTour', () => {
  beforeEach(resetTour);

  it('is false until the preference says true', async () => {
    client.getPreference.mockResolvedValueOnce(null);
    await expect(hasSeenTour()).resolves.toBe(false);
    client.getPreference.mockResolvedValueOnce('true');
    await expect(hasSeenTour()).resolves.toBe(true);
  });

  it('never nags when the preference cannot be read', async () => {
    client.getPreference.mockRejectedValueOnce(new Error('bridge down'));
    await expect(hasSeenTour()).resolves.toBe(true);
  });
});

describe('TourOffer', () => {
  beforeEach(resetTour);

  it('offers the tour on the home screen of a ready wallet that has not seen it', async () => {
    render(<TourOffer appState="wallet_ready" showIntro={false} guideSrc="guide.gif" />);
    expect(await screen.findByTestId('tour-offer')).toBeInTheDocument();
  });

  it('does not offer it once seen', async () => {
    client.getPreference.mockResolvedValue('true');
    render(<TourOffer appState="wallet_ready" showIntro={false} guideSrc="guide.gif" />);
    await waitFor(() => expect(client.getPreference).toHaveBeenCalled());
    expect(screen.queryByTestId('tour-offer')).toBeNull();
  });

  it.each([
    ['a wallet that is not ready', { appState: 'needs_genesis', showIntro: false, screen: 'home' }],
    ['the intro still showing', { appState: 'wallet_ready', showIntro: true, screen: 'home' }],
    ['a screen other than home', { appState: 'wallet_ready', showIntro: false, screen: 'wallet' }],
  ])('does not offer it with %s', async (_label, c) => {
    mockNav.currentScreen = c.screen;
    render(<TourOffer appState={c.appState as never} showIntro={c.showIntro} guideSrc="guide.gif" />);
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByTestId('tour-offer')).toBeNull();
    expect(client.getPreference).not.toHaveBeenCalled();
  });

  it('"Not now" retires the offer and remembers it', async () => {
    render(<TourOffer appState="wallet_ready" showIntro={false} guideSrc="guide.gif" />);
    fireEvent.click(await screen.findByText('Not now'));
    expect(screen.queryByTestId('tour-offer')).toBeNull();
    expect(client.setPreference).toHaveBeenCalledWith(TOUR_SEEN_PREF, 'true');
    expect(practiceMode.enter).not.toHaveBeenCalled();
  });

  it('"Start tour" starts the tour and the offer never comes back in this session', async () => {
    const { rerender } = render(<TourOffer appState="wallet_ready" showIntro={false} guideSrc="guide.gif" />);
    fireEvent.click(await screen.findByText('Start tour'));
    expect(practiceMode.enter).toHaveBeenCalledTimes(1);
    tourStore.end();
    // The preference write may not have landed yet; the offer must stay retired regardless.
    client.getPreference.mockResolvedValue(null);
    rerender(<TourOffer appState="wallet_ready" showIntro={false} guideSrc="guide.gif" />);
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByTestId('tour-offer')).toBeNull();
  });
});

describe('placeDialog', () => {
  const screenBox = { top: 0, left: 0, width: 300, height: 400 };

  it('puts the dialogue in the middle when there is nothing to point at', () => {
    expect(placeDialog(null, screenBox)).toBe('middle');
  });

  it('puts the dialogue on the opposite half from the target', () => {
    expect(placeDialog({ top: 20, left: 0, width: 50, height: 20 }, screenBox)).toBe('bottom');
    expect(placeDialog({ top: 360, left: 0, width: 50, height: 20 }, screenBox)).toBe('top');
  });
});

describe('tour anchors', () => {
  // Every data-tour attribute a step points at must exist in the app, outside the tour itself,
  // so removing one from a screen fails here instead of silently breaking the tour.
  const src = path.resolve(__dirname, '../../..');
  const tourDir = path.resolve(__dirname, '..');

  function sourceFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        return entry.name === '__tests__' || full === tourDir ? [] : sourceFiles(full);
      }
      return /\.tsx?$/.test(entry.name) ? [full] : [];
    });
  }

  const appSource = sourceFiles(src)
    .map((file) => fs.readFileSync(file, 'utf8'))
    .join('\n');

  const anchors = Array.from(
    new Set(
      TOUR_STEPS.flatMap((step) => {
        const found: string[] = [];
        const text = JSON.stringify(step);
        const re = /data-tour=\\"([a-z-]+)\\"/g;
        let m: RegExpExecArray | null = re.exec(text);
        while (m) {
          found.push(m[1]);
          m = re.exec(text);
        }
        return found;
      }),
    ),
  );

  it('the steps name at least the five tour anchors', () => {
    expect(anchors.sort()).toEqual(['contacts-tabs', 'create-token', 'faucet-claim', 'tokens-tabs', 'tutorial-button']);
  });

  it.each(anchors)('data-tour="%s" exists in the app', (anchor) => {
    expect(appSource).toContain(`data-tour="${anchor}"`);
  });
});
