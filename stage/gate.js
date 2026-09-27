// Staging password gate. Client-side only — this keeps casual visitors out
// of the preview, it is not real security. Include in <head> on every
// gated page; redirects to the stage homepage until unlocked.
(function () {
  var KEY = 'stage.unlocked';
  var unlocked = false;
  try { unlocked = sessionStorage.getItem(KEY) === '1'; } catch (e) {}
  if (!unlocked) {
    var root = document.currentScript.src.replace(/gate\.js(\?.*)?$/, '');
    location.replace(root + '?next=' + encodeURIComponent(location.pathname));
  }
})();
