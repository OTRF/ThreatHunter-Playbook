const runWhenDOMLoaded = cb => {
  if (document.readyState != 'loading') {
    cb()
  } else if (document.addEventListener) {
    document.addEventListener('DOMContentLoaded', cb)
  } else {
    document.attachEvent('onreadystatechange', function() {
      if (document.readyState == 'complete') cb()
    })
  }
}

// Helper function to init things quickly
initFunction = function(myfunc) {
  runWhenDOMLoaded(myfunc);
  document.addEventListener('turbolinks:load', myfunc);
};