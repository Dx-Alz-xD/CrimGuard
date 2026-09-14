'use strict';

// A small method + path router. `:name` segments match numeric ids only.
function createRouter() {
  const routes = [];

  function add(method, pattern, handler) {
    const keys = [];
    const source = pattern.replace(/:(\w+)/g, (_, key) => {
      keys.push(key);
      return '(\\d{1,15})';
    });
    routes.push({ method, regex: new RegExp(`^${source}$`), keys, handler });
  }

  // { handler, params } for a match; { allowed } when the path exists under other methods; null otherwise.
  function match(method, pathname) {
    const allowed = [];
    for (const route of routes) {
      const found = route.regex.exec(pathname);
      if (!found) continue;
      if (route.method !== method) {
        allowed.push(route.method);
        continue;
      }
      const params = Object.fromEntries(route.keys.map((key, i) => [key, Number(found[i + 1])]));
      return { handler: route.handler, params };
    }
    return allowed.length ? { allowed } : null;
  }

  const verbs = Object.fromEntries(['get', 'post', 'patch', 'delete'].map((verb) =>
    [verb, (pattern, handler) => add(verb.toUpperCase(), pattern, handler)]));

  return { ...verbs, match };
}

module.exports = { createRouter };
