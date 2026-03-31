// Minimal Leaflet stub for SSR smoke tests. Provides no-op chainable APIs used by GeoMap.
const stubMap = () => {
  const m = {
    setView: () => m,
    on: () => m,
    addLayer: () => m,
    removeLayer: () => m,
    getZoom: () => 17,
    invalidateSize: () => {},
  };
  return m;
};

const chainable = () => ({ addTo: () => chainable(), bindPopup: () => chainable() });

const L = {
  map: (_el, _opts) => stubMap(),
  tileLayer: (_url, _opts) => ({ addTo: () => {} }),
  control: {
    zoom: (_opts) => ({ addTo: () => {} }),
  },
  marker: (_coords, _opts) => ({
    bindPopup: () => ({ addTo: () => ({}) }),
    addTo: () => ({}),
  }),
  divIcon: (_opts) => ({}),
  circle: (_coords, _opts) => ({ addTo: () => ({}) }),
};

module.exports = L;
module.exports.default = L;
