/**
 * Site-wide JS that sets up:
 *
 * [1] MathJax rendering on navigation
 * [2] Sidebar toggling
 * [3] Sidebar scroll preserving
 * [4] Keyboard navigation
 * [5] Right sidebar scroll highlighting / navbar show
 */

const togglerId = 'js-sidebar-toggle'
const textbookId = 'js-textbook'
const togglerActiveClass = 'is-active'
const textbookActiveClass = 'js-show-sidebar'
const mathRenderedClass = 'js-mathjax-rendered'
const icon_path = document.location.origin + `${site_basename}assets`;

const getToggler = () => document.getElementById(togglerId)
const getTextbook = () => document.getElementById(textbookId)

// [1] Run MathJax when Turbolinks navigates to a page.
// When Turbolinks caches a page, it also saves the MathJax rendering. We mark
// each page with a CSS class after rendering to prevent double renders when
// navigating back to a cached page.
document.addEventListener('turbolinks:load', () => {
  const textbook = getTextbook()
  if (window.MathJax && !textbook.classList.contains(mathRenderedClass)) {
    MathJax.Hub.Queue(
      ["resetEquationNumbers", MathJax.InputJax.TeX],
      ['Typeset', MathJax.Hub]
    )
    textbook.classList.add(mathRenderedClass)
  }
})

var initMathAnchors = () => {
  // Disable Turbolinks for MathJax links
  if (typeof MathJax === 'undefined') {
    setTimeout(initMathAnchors, 250);
    return;
  }
  MathJax.Hub.Queue(function () {
    document.querySelectorAll('.MathJax a')
      .forEach(it => it.dataset['turbolinks'] = false);
  });
}

initFunction(initMathAnchors);

/**
 * [2] Toggles sidebar and menu icon
 */
const toggleSidebar = () => {
  const toggler = getToggler()
  const textbook = getTextbook()

  if (textbook.classList.contains(textbookActiveClass)) {
    textbook.classList.remove(textbookActiveClass)
    toggler.classList.remove(togglerActiveClass)
  } else {
    textbook.classList.add(textbookActiveClass)
    toggler.classList.add(togglerActiveClass)
  }
}

/**
 * Keep the variable below in sync with the tablet breakpoint value in
 * _sass/inuitcss/tools/_tools.mq.scss
 *
 */
const autoCloseSidebarBreakpoint = 769

// Set up event listener for sidebar toggle button
const sidebarButtonHandler = () => {
  getToggler().addEventListener('click', toggleSidebar)

  /**
   * Auto-close sidebar on smaller screens after page load.
   *
   * Having the sidebar be open by default then closing it on page load for
   * small screens gives the illusion that the sidebar closes in response
   * to selecting a page in the sidebar. However, it does cause a bit of jank
   * on the first page load.
   *
   * Since we don't want to persist state in between page navigation, this is
   * the best we can do while optimizing for larger screens where most
   * viewers will read the textbook.
   *
   * The code below assumes that the sidebar is open by default.
   */
  if (window.innerWidth < autoCloseSidebarBreakpoint) toggleSidebar()
}

initFunction(sidebarButtonHandler);

/**
 * [3] Preserve sidebar scroll when navigating between pages
 */
let sidebarScrollTop = 0
const getSidebar = () => document.getElementById('js-sidebar')

document.addEventListener('turbolinks:before-visit', () => {
  sidebarScrollTop = getSidebar().scrollTop
})

document.addEventListener('turbolinks:load', () => {
  getSidebar().scrollTop = sidebarScrollTop
})

/**
 * Focus textbook page by default so that user can scroll with spacebar
 */
const focusPage = () => {
  document.querySelector('.c-textbook__page').focus()
}

initFunction(focusPage);

/**
 * [4] Use left and right arrow keys to navigate forward and backwards.
 */
const LEFT_ARROW_KEYCODE = 37
const RIGHT_ARROW_KEYCODE = 39

const getPrevUrl = () => document.getElementById('js-page__nav__prev').href
const getNextUrl = () => document.getElementById('js-page__nav__next').href
const initPageNav = (event) => {
  const keycode = event.which

  if (keycode === LEFT_ARROW_KEYCODE) {
    Turbolinks.visit(getPrevUrl())
  } else if (keycode === RIGHT_ARROW_KEYCODE) {
    Turbolinks.visit(getNextUrl())
  }
};

var keyboardListener = false;
const initListener = () => {
  if (keyboardListener === false) {
    document.addEventListener('keydown', initPageNav)
    keyboardListener = true;
  }
}
initFunction(initListener);

/**
 * [5] Scrolling functions:
 *   * Right sidebar scroll highlighting
 *   * Top navbar hiding for scrolling
 */

var didScroll;

initScrollFunc = function() {
  var content = document.querySelector('.c-textbook__page');
  var topbar = document.getElementById("top-navbar");
  var prevScrollpos = content.scrollTop; // Initializing

  scrollFunc = function() {
    // This is the function that does all the stuff when scrolling happens

    var position = content.scrollTop; // Because we use this differently for sidebar

    // Decide to show the navbar
    var currentScrollPos = content.scrollTop;
    var delta = 10;
    var scrollDiff = prevScrollpos - currentScrollPos;
    if (scrollDiff >= delta) {
      // If we scrolled down, consider showing the menu
      topbar.classList.remove("hidetop")
    } else if (Math.abs(scrollDiff) >= delta) {
      // If we scrolled up, consider hiding the menu
      topbar.classList.add("hidetop")
    } else {
      // Do nothing because we didn't scroll enough
    }
    prevScrollpos = currentScrollPos;

    // Highlight the right sidebar section
    position = position + (window.innerHeight / 4);  // + Manual offset

    content.querySelectorAll('h2, h3').forEach((header, index) => {
      // Highlight based on location from the top of the screen
      var target = header.getBoundingClientRect().top
      var pixelOffset = 300;  // Number of pixels from top to be highlighted
      var id = header.id;
      if (target < pixelOffset) {
        var query = 'ul.toc__menu a[href="#' + id + '"]';
        document.querySelectorAll('ul.toc__menu li').forEach((item) => {item.classList.remove('active')});
        document.querySelectorAll(query).forEach((item) => {item.parentElement.classList.add('active')});
      }
    });
  }

  // Our event listener just sets "yep, I scrolled" to true.
  // The interval function will set it to false after it runs.
  content.addEventListener('scroll', () => {didScroll = true;});
  scrollWait = 250;
  setInterval(() => {
    if (didScroll) {
      scrollFunc();
      didScroll = false;
    }
  }, scrollWait)
}

initFunction(initScrollFunc);


/**
 * [6] Left sidebar highlight
 *   Loop through the left sidebar links and show / highlight the relevant ones
 */

var updateSidebar = () => {
  var currentUrl = window.location.href;
  var chapters = document.querySelector('ul.c-sidebar__chapters')
  chapters.querySelectorAll('li.c-sidebar__chapter').forEach((chapter, index) => {
    var sections = chapter.nextElementSibling;
    if (currentUrl.endsWith(chapter.dataset.url + '.html')) {
      chapter.querySelector('a').classList.add('c-sidebar__entry--active')
      if (sections.classList.contains('c-sidebar__sections')) {
        sections.classList.remove('u-hidden-visually');
      }
    }

    // Loop through sections to highlight as needed
    if (sections) {
      sections.querySelectorAll('li.c-sidebar__section').forEach((section, ix_section) => {
        var subsections = section.nextElementSibling;

        // If we're in a top-level section page, show the section
        if (currentUrl.endsWith(section.dataset.url + '.html')) {
          section.querySelector('a').classList.add('c-sidebar__entry--active');
          sections.classList.remove('u-hidden-visually');

          // If we have subsections, show them if we've clicked the parent section
          if (subsections.classList.contains('c-sidebar__subsections')) {
            subsections.classList.remove('u-hidden-visually');
          }
        }

        // Loop through subections to highlight if needed
        if (subsections) {
          subsections.querySelectorAll('li.c-sidebar__subsection').forEach((subsection, ix_subsection) => {
            if (currentUrl.endsWith(subsection.dataset.url + '.html')) {
              subsection.querySelector('a').classList.add('c-sidebar__entry--active');
              sections.classList.remove('u-hidden-visually');
              subsections.classList.remove('u-hidden-visually');
            }
          })
        }
      })
    }
  });
}
initFunction(updateSidebar);
