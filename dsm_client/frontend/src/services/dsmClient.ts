// SPDX-License-Identifier: MIT OR Apache-2.0

// The client the screens call: the flat namespace in '@/dsm/index', re-exported
// here so tests that mock '../../dsm/index' can override its methods.
export { dsmClient } from '../dsm/index';
