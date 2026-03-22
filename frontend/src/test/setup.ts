import "@testing-library/jest-dom";
import { webcrypto } from "node:crypto";

// Polyfill window.crypto for Vitest/jsdom
Object.defineProperty(window, "crypto", {
  value: webcrypto,
});

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});
