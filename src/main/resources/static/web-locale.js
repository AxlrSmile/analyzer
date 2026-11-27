'use strict';

(() => {
  const key = 'csa-web-language';
  const chooser = document.getElementById('languageSelect');
  const catalog = window.WebLanguages;
  const renderers = new WeakMap();
  const attributes = ['title', 'aria-label', 'placeholder'];
  let language = 'ru';
  try {
    const saved = localStorage.getItem(key);
    if (['ru', 'en', 'kk'].includes(saved)) language = saved;
  } catch (_) { /* Storage is optional. */ }

  function translate(source) {
    return catalog[source]?.[language === 'en' ? 0 : language === 'kk' ? 1 : -1] ?? source;
  }

  function bind(node, property, render) {
    let bindings = renderers.get(node);
    if (!bindings) renderers.set(node, bindings = new Map());
    bindings.set(property, render);
    render();
  }

  function text(node, message) {
    bind(node, 'text', () => { node.textContent = message(); });
    return node;
  }

  // Register only markup labels at startup. Source code and scanner output are rendered separately.
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const label = node.data.trim();
    if (!Object.hasOwn(catalog, label)) continue;
    const parts = node.data.match(/^(\s*)([\s\S]*?)(\s*)$/);
    const labelNode = node;
    bind(node, 'text', () => { labelNode.data = parts[1] + translate(label) + parts[3]; });
  }
  for (const element of document.querySelectorAll('[title], [aria-label], [placeholder]')) {
    for (const name of attributes) {
      const label = element.getAttribute(name);
      if (Object.hasOwn(catalog, label)) {
        bind(element, name, () => element.setAttribute(name, translate(label)));
      }
    }
  }

  function update() {
    document.documentElement.lang = language;
    chooser.value = language;
    const nodes = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let node = nodes.nextNode(); node; node = nodes.nextNode()) {
      for (const render of renderers.get(node)?.values() ?? []) render();
    }
  }

  chooser.addEventListener('change', () => {
    language = chooser.value;
    try { localStorage.setItem(key, language); } catch (_) { /* Storage is optional. */ }
    update();
  });
  function attribute(node, name, message) {
    bind(node, name, () => node.setAttribute(name, message()));
  }

  window.WebLocale = { t: translate, text, attribute, get language() { return language; } };
  update();
})();
