// Initialize MathJax with the notebook config
// Taken from https://github.com/jupyter/notebook/blob/master/notebook/static/notebook/js/mathjaxutils.js#L13
var initMathJax = () => {
    if (window.MathJax) {
        // MathJax loaded
        MathJax.Hub.Config({
            tex2jax: {
                inlineMath: [ ['$','$'], ["\\(","\\)"] ],
                displayMath: [ ['$$','$$'], ["\\[","\\]"] ],
                processEscapes: true,
                processEnvironments: true
            },
            MathML: {
                extensions: ['content-mathml.js']
            },
            // Center justify equations in code and markdown cells. Elsewhere
            // we use CSS to left justify single line equations in code cells.
            displayAlign: 'center',
            "HTML-CSS": {
                availableFonts: [],
                imageFont: null,
                preferredFont: null,
                webFont: "STIX-Web",
                styles: {'.MathJax_Display': {"margin": 0}},
                linebreaks: { automatic: true }
            },
        });
        MathJax.Hub.Configured();
    }
}

// Helper function to run when the DOM is finished
const mystNBRunWhenDOMLoaded = cb => {
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
mystNBRunWhenDOMLoaded(initMathJax)
