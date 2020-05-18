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

sbRunWhenDOMLoaded(initTooltips)
sbRunWhenDOMLoaded(initTriggerNavBar)
sbRunWhenDOMLoaded(scrollToActive)
