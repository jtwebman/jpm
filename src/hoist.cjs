// Written by jpm. Packages in the global store resolve from the store, so an import of a package
// they did not declare falls back to the project's hidden hoist, beside this file. CommonJS
// gets the same from NODE_PATH.
const m = require('node:module');
const parentURL = require('node:url').pathToFileURL(__filename).href;
const retry = (s, e) => e?.code === 'ERR_MODULE_NOT_FOUND' && !/^([./#]|[a-z][a-z\d+.-]*:)/i.test(s);
if (m.registerHooks) {
  m.registerHooks({
    resolve(s, c, next) {
      try {
        return next(s, c);
      } catch (e) {
        if (!retry(s, e)) throw e;
        return next(s, { ...c, parentURL });
      }
    },
  });
} else if (m.register) {
  // Node before 22.15: the same hook, run off-thread.
  const hook = `const retry = ${retry}; export async function resolve(s, c, next) {
    try { return await next(s, c); } catch (e) {
      if (!retry(s, e)) throw e;
      return next(s, { ...c, parentURL: ${JSON.stringify(parentURL)} });
    }
  }`;
  m.register('data:text/javascript,' + encodeURIComponent(hook));
}
