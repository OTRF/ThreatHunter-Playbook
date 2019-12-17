const initToc = () => {
  if (window.tocbot === undefined) {
    setTimeout(initToc, 250);
    return;
  }

  // Check whether we have any sidebar content. If not, then show the sidebar earlier.
  var SIDEBAR_CONTENT_TAGS = ['.tag_full_width', '.tag_popout'];
  var sidebar_content_query = SIDEBAR_CONTENT_TAGS.join(', ')
  if (document.querySelectorAll(sidebar_content_query).length === 0) {
    document.querySelector('nav.onthispage').classList.add('no_sidebar_content')
  }

  // Initialize the TOC bot if we have TOC headers
  const tocContent = '.c-textbook__content';
  const tocHeaders = 'h1, h2, h3';
  var headers = document.querySelector(tocContent).querySelectorAll(tocHeaders);
  if (headers.length > 0) {
    document.querySelector('aside.sidebar__right').classList.remove('hidden');
    tocbot.init({
      tocSelector: 'nav.onthispage',
      contentSelector: tocContent,
      headingSelector: tocHeaders,
      orderedList: false,
      collapseDepth: 6,
      listClass: 'toc__menu',
      activeListItemClass: " ",  // Not using, can't be empty
      activeLinkClass: " ", // Not using, can't be empty
    });
  } else {
    document.querySelector('aside.sidebar__right').classList.add('hidden');
  }

  // Disable Turbolinks for TOC links
  document.querySelectorAll('.toc-list-item a')
    .forEach(it => it.dataset['turbolinks'] = false);
}
initFunction(initToc);
