# Creating book content

The two kinds of files that contain course content are:

* Jupyter Notebooks
* Markdown files

Each are contained in the `content/` folder and referenced from `_data/toc.yml`.

If the file is markdown, it will be copied over with front-matter YAML added so
that Jekyll can parse it

## Sidebars with Jekyll

You may notice that there's a sidebar to the right (if your screen is wide enough).
These are automatically generated from the headers that are present in your page.
The sidebar will automatically capture all 2nd and 3rd level section headers.
The best way to designate these headers is with `#` characters at the beginning
of a line.

### Here's a third-level header

This section is here purely to demonstrate the third-level header of the
rendered page!

## Embedding media

### Adding images

You can reference external media like images from your markdown file. If you use
relative paths, then they will continue to work when the markdown files are copied over,
so long as they point to a file that's inside of the repository.

Here's an image relative to the site root

![](../images/C-3PO_droid.png)

### Adding movies

You can even embed references to movies on the web! For example, here's a little gif for you!

![](https://media.giphy.com/media/yoJC2A59OCZHs1LXvW/giphy.gif)

This will be included in your website when it is built.