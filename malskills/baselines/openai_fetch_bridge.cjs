'use strict';

const configuredBase = (process.env.MALSKILLS_OPENAI_BASE_URL || '').replace(/\/$/, '');

if (configuredBase && typeof globalThis.fetch === 'function') {
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = function fetchWithConfiguredOpenAIBase(input, init) {
    if (typeof input === 'string' && input.startsWith('https://api.openai.com/v1/')) {
      input = `${configuredBase}/${input.slice('https://api.openai.com/v1/'.length)}`;
    } else if (input instanceof URL && input.href.startsWith('https://api.openai.com/v1/')) {
      input = new URL(`${configuredBase}/${input.href.slice('https://api.openai.com/v1/'.length)}`);
    }
    return nativeFetch.call(globalThis, input, init);
  };
}
