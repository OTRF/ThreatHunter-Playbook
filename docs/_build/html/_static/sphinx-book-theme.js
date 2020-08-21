// Navbar toggle button
var initTriggerNavBar = () => {
    if ($(window).width() < 768) {
        $("#navbar-toggler").trigger("click")
    }
}


// NavBar scrolling
var scrollToActive = () => {
  var navbar = document.getElementById('site-navigation')
  var active_pages = navbar.querySelectorAll(".active")
  var active_page = active_pages[active_pages.length-1]
  // Only scroll the navbar if the active link is lower than 50% of the page
  if (active_page.offsetTop > ($(window).height() * .5)) {
    navbar.scrollTop = active_page.offsetTop - ($(window).height() * .2)
  }
}

// Helper function to run when the DOM is finished
var sbRunWhenDOMLoaded = cb => {
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

// Toggle full-screen with button
function toggleFullScreen() {
  var navToggler = $("#navbar-toggler");
  if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen();
      if (!navToggler.hasClass("collapsed")) {
        navToggler.click();
      }
  } else {
    if (document.exitFullscreen) {
      document.exitFullscreen();
      if (navToggler.hasClass("collapsed")) {
        navToggler.click();
      }
    }
  }
}

// Enable tooltips
var initTooltips = () => {
  $(document).ready(function(){
    $('[data-toggle="tooltip"]').tooltip();
  });
}

var initTocHide = () => {
  // Hide the TOC when we scroll down
  var scrollTimeout;
  var throttle = 200;  // in milliseconds
  var tocHeight = $("#bd-toc-nav").outerHeight(true) + $(".bd-toc").outerHeight(true);
  var hideTocAfter = tocHeight + 200;  // Height of TOC + some extra padding
  var checkTocScroll = function () {
      var margin_content = $(".margin, .tag_margin, .full-width, .full_width, .tag_full-width, .tag_full_width, .sidebar, .tag_sidebar, .popout, .tag_popout");
      margin_content.each((index, item) => {
        // Defining the boundaries that we care about for checking TOC hiding
        var topOffset = $(item).offset().top - $(window).scrollTop();
        var bottomOffset = topOffset + $(item).outerHeight(true);

        // Check whether we should hide the TOC (if it overlaps with a margin content)
        var topOverlaps = ((topOffset >= 0) && (topOffset < hideTocAfter));
        var bottomOverlaps = ((bottomOffset >= 0) && (bottomOffset < hideTocAfter));
        var removeToc = (topOverlaps || bottomOverlaps);
        if (removeToc && window.pageYOffset > 20) {
          $("div.bd-toc").removeClass("show")
          return false
        } else {
          $("div.bd-toc").addClass("show")
        };
      })
  };

  $(window).on('scroll', function () {
      if (!scrollTimeout) {
          scrollTimeout = setTimeout(function () {
              checkTocScroll();
              scrollTimeout = null;
          }, throttle);
      }
  });
}

var initThebeSBT = () => {
  var title  = $("div.section h1")[0]
  if (!$(title).next().hasClass("thebe-launch-button")) {
    $("<button class='thebe-launch-button'></button>").insertAfter($(title))
  }
  initThebe();
}

sbRunWhenDOMLoaded(initTooltips)
sbRunWhenDOMLoaded(initTriggerNavBar)
sbRunWhenDOMLoaded(scrollToActive)
sbRunWhenDOMLoaded(initTocHide)
