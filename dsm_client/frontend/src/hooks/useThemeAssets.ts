/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import type { ThemeName } from '../utils/theme';

const chameleonMap: Record<ThemeName, string> = {
  stateboy: 'images/vaulthunters/chameleon-lime.gif',
  pocket: 'images/vaulthunters/chameleon.gif',
  light: 'images/vaulthunters/chameleon-cyan.GIF',
  berry: 'images/vaulthunters/chameleon-pink.GIF',
  grape: 'images/vaulthunters/chameleon-purple.GIF',
  dandelion: 'images/vaulthunters/chameleon-yellow.gif',
  orange: 'images/vaulthunters/chameleon-orange.gif',
  teal: 'images/vaulthunters/chameleon-blue.GIF',
  kiwi: 'images/vaulthunters/chameleon-lime.gif',
  greyscale: 'images/vaulthunters/chameleon-grey.gif',
  inverted: 'images/vaulthunters/chameleon-inverted.gif',
  crimson: 'images/vaulthunters/chameleon-red.gif',
};

const introGifMap: Record<ThemeName, string> = {
  stateboy: 'images/cutscenes/stateboy.gif',
  pocket: 'images/cutscenes/stateboy.gif',
  light: 'images/cutscenes/stateboy_cyan.gif',
  berry: 'images/cutscenes/stateboy_pink.gif',
  grape: 'images/cutscenes/stateboy_purple.gif',
  dandelion: 'images/cutscenes/stateboy_yellow.gif',
  orange: 'images/cutscenes/stateboy_orange.gif',
  teal: 'images/cutscenes/stateboy_blue.gif',
  kiwi: 'images/cutscenes/stateboy_lime.gif',
  greyscale: 'images/cutscenes/stateboy_grey.gif',
  inverted: 'images/cutscenes/stateboy_grey.gif',
  crimson: 'images/cutscenes/stateboy_red.gif',
};

const eraTokenMap: Record<ThemeName, string> = {
  stateboy: 'images/logos/era_token_gb.gif',
  pocket: 'images/logos/era_token_gb.gif',
  light: 'images/logos/era_token_gb_cyan.gif',
  berry: 'images/logos/era_token_gb_pink.gif',
  grape: 'images/logos/era_token_gb_purple.gif',
  dandelion: 'images/logos/era_token_gb_yellow.gif',
  orange: 'images/logos/era_token_gb_orange.gif',
  teal: 'images/logos/era_token_gb_blue.gif',
  kiwi: 'images/logos/era_token_gb_lime.gif',
  greyscale: 'images/logos/era_token_gb_grey.gif',
  inverted: 'images/logos/era_token_gb_inverted.gif',
  crimson: 'images/logos/era_token_gb_red.gif',
};

const btcLogoMap: Record<ThemeName, string> = {
  stateboy: 'images/logos/btc-logo.gif',
  pocket: 'images/logos/btc-logo.gif',
  light: 'images/logos/btc-logo-cyan.gif',
  berry: 'images/logos/btc-logo-pink.gif',
  grape: 'images/logos/btc-logo-purple.gif',
  dandelion: 'images/logos/btc-logo-yellow.gif',
  orange: 'images/logos/btc-logo-orange.gif',
  teal: 'images/logos/btc-logo-blue.gif',
  kiwi: 'images/logos/btc-logo-lime.gif',
  greyscale: 'images/logos/btc-logo-grey.gif',
  inverted: 'images/logos/btc-logo-inverted.gif',
  crimson: 'images/logos/btc-logo-red.gif',
};

const bricksMap: Record<ThemeName, string> = {
  stateboy: 'images/vaulthunters/bricks2.svg',
  pocket: 'images/vaulthunters/bricks2.svg',
  light: 'images/vaulthunters/bricks2_cyan.png',
  berry: 'images/vaulthunters/bricks2_pink.png',
  grape: 'images/vaulthunters/bricks2_purple.png',
  dandelion: 'images/vaulthunters/bricks2_yellow.png',
  orange: 'images/vaulthunters/bricks2_orange.png',
  teal: 'images/vaulthunters/bricks2_blue.png',
  kiwi: 'images/vaulthunters/bricks2_lime.png',
  greyscale: 'images/vaulthunters/bricks2_grey.png',
  inverted: 'images/vaulthunters/bricks2_grey.png',
  crimson: 'images/vaulthunters/bricks2_red.png',
};

const dsmLogoMap: Record<ThemeName, string> = {
  stateboy: 'images/logos/dsm-stateboy-on-screen-logo.svg',
  pocket: 'images/logos/dsm-stateboy-on-screen-logo.svg',
  light: 'images/logos/dsm-stateboy-on-screen-logo_cyan.png',
  berry: 'images/logos/dsm-stateboy-on-screen-logo_pink.png',
  grape: 'images/logos/dsm-stateboy-on-screen-logo_purple.png',
  dandelion: 'images/logos/dsm-stateboy-on-screen-logo_yellow.png',
  orange: 'images/logos/dsm-stateboy-on-screen-logo_orange.png',
  teal: 'images/logos/dsm-stateboy-on-screen-logo_blue.png',
  kiwi: 'images/logos/dsm-stateboy-on-screen-logo_lime.png',
  greyscale: 'images/logos/dsm-stateboy-on-screen-logo_grey.png',
  inverted: 'images/logos/dsm-stateboy-on-screen-logo_inverted.png',
  crimson: 'images/logos/dsm-stateboy-on-screen-logo_red.png',
};

const themeChameleon = (t: ThemeName) => chameleonMap[t] || 'images/vaulthunters/chameleon.gif';
const themeIntroGif = (t: ThemeName) => introGifMap[t] || 'images/cutscenes/stateboy.gif';
const themeEraToken = (t: ThemeName) => eraTokenMap[t] || 'images/logos/era_token_gb.gif';
const themeBtcLogo = (t: ThemeName) => btcLogoMap[t] || 'images/logos/btc-logo.gif';
const themeBricks = (t: ThemeName) => bricksMap[t] || 'images/vaulthunters/bricks2.svg';
const themeDsmLogo = (t: ThemeName) => dsmLogoMap[t] || 'images/logos/dsm-stateboy-on-screen-logo.svg';

export function useThemeAssets(theme: ThemeName) {
  const [chameleonSrc, setChameleonSrc] = useState<string>(themeChameleon(theme));

  useEffect(() => {
    setChameleonSrc(themeChameleon(theme));
  }, [theme]);

  const introGifSrc = useMemo(() => themeIntroGif(theme), [theme]);
  const eraTokenSrc = useMemo(() => themeEraToken(theme), [theme]);
  const btcLogoSrc = useMemo(() => themeBtcLogo(theme), [theme]);
  const bricksSrc = useMemo(() => themeBricks(theme), [theme]);
  const dsmLogoSrc = useMemo(() => themeDsmLogo(theme), [theme]);

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.style.setProperty('--bricks-bg', `url('${bricksSrc}')`);
    }
  }, [bricksSrc]);

  return {
    chameleonSrc,
    setChameleonSrc,
    introGifSrc,
    eraTokenSrc,
    btcLogoSrc,
    bricksSrc,
    dsmLogoSrc,
  };
}
