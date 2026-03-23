import { IAMService } from "@tidecloak/js";

let _dpopEnabled = false;

export function setDpopEnabled(enabled: boolean) {
  _dpopEnabled = enabled;
}

export function isDpopEnabled() {
  return _dpopEnabled;
}

/**
 * Fetch wrapper that uses IAMService.secureFetch when DPoP is enabled,
 * otherwise falls back to the standard fetch API.
 */
export function appFetch(input: string, init?: RequestInit): Promise<Response> {
  if (_dpopEnabled) {
    return IAMService.secureFetch(input, init);
  }
  return fetch(input, init);
}
