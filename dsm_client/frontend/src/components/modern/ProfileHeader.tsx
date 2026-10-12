// SPDX-License-Identifier: Apache-2.0
// The owner's banner, photo and name at the top of the Modern skin: on the
// Wallet tab it is who the wallet is (tap it for your card); on My Card the
// banner and the photo are tapped to choose a picture from the phone, which
// is then framed (moved and zoomed) before it is kept.

import React, { useEffect, useId, useState } from 'react';
import { loadImageFile } from '../../utils/imageCrop';
import ImageCropper from './ImageCropper';
import { Icon } from './parts';
import { ownCardStore, useOwnCard } from './ownCard';

/** Sizes the pictures are kept at: the photo square, the banner 3:1. */
const PHOTO_SIDE = 320;
const BANNER_W = 1080;
const BANNER_H = 360;

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

type Props =
  /** The Wallet tab's header: tapping it opens your card. */
  | { mode: 'show'; onOpen: () => void }
  /** My Card's header: the banner and the photo are chosen here. */
  | { mode: 'edit' };

export default function ProfileHeader(props: Props): React.JSX.Element {
  const card = useOwnCard();
  const id = useId();
  const [said, setSaid] = useState<string | null>(null);
  // A picture being framed before it is kept.
  const [framing, setFraming] = useState<{ which: 'photo' | 'banner'; image: HTMLImageElement; release: () => void } | null>(null);

  useEffect(() => {
    if (card.kind === 'unread') {
      ownCardStore.load().then(
        () => undefined,
        (e: unknown) => setSaid(messageOf(e)),
      );
    }
  }, [card.kind]);

  const name = card.kind === 'read' && card.name.length > 0 ? card.name : null;
  const photo = card.kind === 'read' ? card.photo : null;
  const banner = card.kind === 'read' ? card.banner : null;

  const choose = (which: 'photo' | 'banner', file: File) => {
    setSaid(null);
    loadImageFile(file).then(
      ({ image, release }) => setFraming({ which, image, release }),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const endFraming = () => {
    framing?.release();
    setFraming(null);
  };

  const keep = (which: 'photo' | 'banner', picture: string) => {
    endFraming();
    // Kept quietly: the header shows the new picture; only a failure is said.
    ownCardStore.setPicture(which, picture).then(
      () => setSaid(null),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const remove = (which: 'photo' | 'banner') => {
    ownCardStore.setPicture(which, null).then(
      () => setSaid(null),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const bannerStyle = banner !== null ? { backgroundImage: `url(${banner})` } : undefined;
  const face = photo !== null
    ? <img src={photo} alt="" />
    : <span>{name !== null ? name.trim().slice(0, 1).toUpperCase() : <Icon name="person" />}</span>;

  if (props.mode === 'show') {
    return (
      <button type="button" className="s-profile" onClick={props.onOpen} aria-label={name !== null ? `${name}: your card` : 'Your card'}>
        <span className="s-profile-banner" style={bannerStyle} />
        <span className="s-profile-photo">{face}</span>
        <span className="s-profile-name">{name !== null ? name : 'Add your name'}</span>
      </button>
    );
  }

  return (
    <section className="s-profile s-profile-edit" aria-label="Your banner and photo">
      <input
        id={`${id}-banner`}
        type="file"
        className="sb-file"
        accept="image/png,image/jpeg,image/webp"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file !== undefined) choose('banner', file);
        }}
      />
      <label htmlFor={`${id}-banner`} className="s-profile-banner" style={bannerStyle} aria-label="Choose your banner">
        <span className="s-profile-hint">{banner !== null ? 'Change banner' : 'Add a banner'}</span>
      </label>
      <input
        id={`${id}-photo`}
        type="file"
        className="sb-file"
        accept="image/png,image/jpeg,image/webp"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file !== undefined) choose('photo', file);
        }}
      />
      <label htmlFor={`${id}-photo`} className="s-profile-photo" aria-label="Choose your photo">
        {face}
        <span className="s-profile-camera" aria-hidden>+</span>
      </label>
      <div className="s-profile-name">{name !== null ? name : 'Your name'}</div>
      <div className="s-profile-actions">
        {photo !== null ? <button type="button" className="s-chip" onClick={() => remove('photo')}>Remove photo</button> : null}
        {banner !== null ? <button type="button" className="s-chip" onClick={() => remove('banner')}>Remove banner</button> : null}
      </div>
      <p className="s-hint" style={{ textAlign: 'center' }}>Your photo and banner stay on this phone. Your code shares your name, email and phone.</p>
      {said !== null ? <p className="s-hint" role="status" style={{ textAlign: 'center' }}>{said}</p> : null}
      {framing !== null ? (
        <ImageCropper
          image={framing.image}
          shape={framing.which === 'photo' ? 'circle' : 'banner'}
          width={framing.which === 'photo' ? PHOTO_SIDE : BANNER_W}
          height={framing.which === 'photo' ? PHOTO_SIDE : BANNER_H}
          onSave={(picture) => keep(framing.which, picture)}
          onCancel={endFraming}
        />
      ) : null}
    </section>
  );
}
