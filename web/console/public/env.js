// Runtime configuration (NoOps). In a deployed container this file is
// regenerated at startup from KSEAL_API_BASE_URL by docker-entrypoint.sh so a
// single prebuilt image is configurable per environment. Left empty here so
// local dev falls back to the Vite-inlined VITE_KSEAL_API_BASE_URL.
window.__KSEAL_ENV__ = window.__KSEAL_ENV__ || {};
