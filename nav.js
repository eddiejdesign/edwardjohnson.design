// Sticky top bar: hides while scrolling down, returns (with its translucent
// background) while scrolling up, and goes back to transparent at the top.
(function () {
  var bar = document.querySelector('.topbar');
  if (!bar) return;
  var THRESHOLD = 6;
  var last = window.scrollY;
  var ticking = false;

  function update() {
    var y = window.scrollY;
    if (y <= 0) {
      bar.classList.remove('is-hidden', 'is-solid');
    } else if (y > last + THRESHOLD && y > bar.offsetHeight) {
      if (!bar.contains(document.activeElement)) bar.classList.add('is-hidden');
    } else if (y < last - THRESHOLD) {
      bar.classList.remove('is-hidden');
      bar.classList.add('is-solid');
    }
    if (Math.abs(y - last) > THRESHOLD || y <= 0) last = y;
    ticking = false;
  }

  window.addEventListener('scroll', function () {
    if (!ticking) {
      ticking = true;
      requestAnimationFrame(update);
    }
  }, { passive: true });

  // Keyboard users tabbing into the bar should always see it.
  bar.addEventListener('focusin', function () {
    bar.classList.remove('is-hidden');
  });
})();
