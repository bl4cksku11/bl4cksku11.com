/* Theme init — read localStorage + system preference before body renders.
   Inline this in <head> of every page (or reference before other assets)
   to avoid FOUC. Also exposes window.toggleTheme(). */
(function () {
  var KEY = 'theme';
  var html = document.documentElement;
  function apply(t) {
    html.setAttribute('data-theme', t);
    try { localStorage.setItem(KEY, t); } catch (_) {}
  }
  var stored = null;
  try { stored = localStorage.getItem(KEY); } catch (_) {}
  var initial;
  if (stored === 'light' || stored === 'dark') {
    initial = stored;
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    initial = 'light';
  } else {
    initial = 'dark';
  }
  apply(initial);

  window.toggleTheme = function () {
    var cur = html.getAttribute('data-theme') || 'dark';
    apply(cur === 'dark' ? 'light' : 'dark');
  };

  // React to system preference changes only when user has not chosen
  if (window.matchMedia && !stored) {
    var mq = window.matchMedia('(prefers-color-scheme: light)');
    var handler = function (e) {
      var s;
      try { s = localStorage.getItem(KEY); } catch (_) {}
      if (s === 'light' || s === 'dark') return;
      apply(e.matches ? 'light' : 'dark');
    };
    if (mq.addEventListener) mq.addEventListener('change', handler);
    else if (mq.addListener) mq.addListener(handler);
  }
})();
