// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The bridge object the page calls, installed by the iOS host at document
// start, in the page's own world. It carries the same keys `public/index.html`
// installs on `window.DsmBridge` for Android (the frontend's `AndroidBridgeV3`
// names exactly them), so the React bundle is the same on both platforms.
//
// Android's page talks to Kotlin over a MessagePort that moves ArrayBuffers.
// WebKit's script-message channel moves strings and dictionaries only, so
// every byte crosses it as Base32 Crockford, DSM's one textual form of bytes,
// and is bytes again on the other side. Nothing here reads a protobuf: a
// request's bytes go to the host whole, the host's answer comes back whole,
// and the page decodes it with its own generated types as it does on Android.
(function () {
  if (window.DsmBridge && window.DsmBridge.__binary) return;

  var messageHandlers = window.webkit && window.webkit.messageHandlers;
  var handler = messageHandlers && messageHandlers.dsm;
  var handlerPosts = !!handler && typeof handler.postMessage === 'function';

  // The event bridge in the bundle loads after this script and drains what
  // arrived before it listened.
  window.__DSM_EVENT_BUFFER__ = [];

  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  var LOOKUP = {};
  for (var i = 0; i < ALPHABET.length; i++) {
    LOOKUP[ALPHABET[i]] = i;
    LOOKUP[ALPHABET[i].toLowerCase()] = i;
  }

  function encodeBase32(bytes) {
    var out = '';
    var buffer = 0;
    var bitsLeft = 0;
    for (var k = 0; k < bytes.length; k++) {
      buffer = ((buffer << 8) | bytes[k]) >>> 0;
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        out += ALPHABET[(buffer >>> (bitsLeft - 5)) & 0x1f];
        bitsLeft -= 5;
      }
    }
    if (bitsLeft > 0) out += ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f];
    return out;
  }

  function decodeBase32(text) {
    var out = [];
    var buffer = 0;
    var bitsLeft = 0;
    for (var k = 0; k < text.length; k++) {
      var value = LOOKUP[text[k]];
      if (value === undefined) continue;
      buffer = ((buffer << 5) | value) >>> 0;
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        out.push((buffer >>> (bitsLeft - 8)) & 0xff);
        bitsLeft -= 8;
      }
    }
    return new Uint8Array(out);
  }

  function toBytes(payload) {
    return payload instanceof Uint8Array ? payload : new Uint8Array(0);
  }

  // One message to the host; the host's reply is the Base32 of its answer,
  // and a refusal rejects with the host's reason.
  function post(body) {
    if (!handlerPosts) return Promise.reject(new Error('DSM binary bridge not ready'));
    return handler.postMessage(body).then(function (reply) {
      return decodeBase32(String(reply));
    });
  }

  // One BridgeRpcRequest, as bytes; the BridgeRpcResponse the host answered, as bytes.
  function sendMessageBin(requestBytes) {
    return post({ kind: 'bin', request: encodeBase32(toBytes(requestBytes)) });
  }

  // One bridge method by name; the success bytes, or a rejection with the error's message.
  function callBridgeMethod(method, payload) {
    return post({ kind: 'rpc', method: method, payload: encodeBase32(toBytes(payload)) });
  }

  window.DsmBridge = {
    __binary: handlerPosts,
    isAvailable: function () { return handlerPosts; },
    sendMessageBin: sendMessageBin,
    ingress: function (payload) { return callBridgeMethod('nativeBoundaryIngress', payload); },
    hostRequest: function (payload) { return callBridgeMethod('nativeHostRequest', payload); },
    getBridgeStatus: function () { return handlerPosts ? 3 : 0; },
  };

  // The host's events, by topic: what Kotlin posts as AppRouterPayload bytes
  // on Android arrives here already split.
  window.__dsmHostEvent = function (topic, payloadBase32) {
    var payload = decodeBase32(String(payloadBase32));
    if (window.__DSM_EVENT_BUFFER__) window.__DSM_EVENT_BUFFER__.push({ topic: topic, payload: payload });
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: topic, payload: payload } }));
  };

  // The host's NativeHostEvent bytes (a QR result, a picked contact).
  window.__dsmNativeHostEvent = function (eventBase32) {
    window.dispatchEvent(new CustomEvent('dsm-native-host-event-bin', { detail: { payload: decodeBase32(String(eventBase32)) } }));
  };
})();
