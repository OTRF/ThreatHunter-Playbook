// Localization support
const messages = {
  'en': {
    'copy': 'Copy',
    'copy_to_clipboard': 'Copy to clipboard',
    'copy_success': 'Copied!',
    'copy_failure': 'Failed to copy',
  },
  'es' : {
    'copy': 'Copiar',
    'copy_to_clipboard': 'Copiar al portapapeles',
    'copy_success': '¡Copiado!',
    'copy_failure': 'Error al copiar',
  },
  'de' : {
    'copy': 'Kopieren',
    'copy_to_clipboard': 'In die Zwischenablage kopieren',
    'copy_success': 'Kopiert!',
    'copy_failure': 'Fehler beim Kopieren',
  }
}

let locale = 'en'
if( document.documentElement.lang !== undefined
    && messages[document.documentElement.lang] !== undefined ) {
  locale = document.documentElement.lang
}

/**
 * Set up copy/paste for code blocks
 */

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

const codeCellId = index => `codecell${index}`

// Clears selected text since ClipboardJS will select the text when copying
const clearSelection = () => {
  if (window.getSelection) {
    window.getSelection().removeAllRanges()
  } else if (document.selection) {
    document.selection.empty()
  }
}

// Changes tooltip text for two seconds, then changes it back
const temporarilyChangeTooltip = (el, newText) => {
  const oldText = el.getAttribute('data-tooltip')
  el.setAttribute('data-tooltip', newText)
  setTimeout(() => el.setAttribute('data-tooltip', oldText), 2000)
}

// Callback when a copy button is clicked. Will be passed the node that was clicked
// should then grab the text and replace pieces of text that shouldn't be used in output
var copyTargetText = (trigger) => {
  var target = document.querySelector(trigger.attributes['data-clipboard-target'].value);
  var textContent = target.innerText.split('\n');
  var copybuttonPromptText = ''; // Inserted from config
  var onlyCopyPromptLines = true; // Inserted from config
  var removePrompts = true; // Inserted from config

  // Text content line filtering based on prompts (if a prompt text is given)
  if (copybuttonPromptText.length > 0) {
    // If only copying prompt lines, remove all lines that don't start w/ prompt
    if (onlyCopyPromptLines) {
      linesWithPrompt = textContent.filter((line) => {
        return line.startsWith(copybuttonPromptText) || (line.length == 0); // Keep newlines
      });
      // Check to make sure we have at least one non-empty line
      var nonEmptyLines = linesWithPrompt.filter((line) => {return line.length > 0});
      // If we detected lines w/ prompt, then overwrite textContent w/ those lines
      if ((linesWithPrompt.length > 0) && (nonEmptyLines.length > 0)) {
        textContent = linesWithPrompt;
      }
    }
    // Remove the starting prompt from any remaining lines
    if (removePrompts) {
      textContent.forEach((line, index) => {
        if (line.startsWith(copybuttonPromptText)) {
          textContent[index] = line.slice(copybuttonPromptText.length);
        }
      });
    }
  }
  textContent = textContent.join('\n');
  // Remove a trailing newline to avoid auto-running when pasting
  if (textContent.endsWith("\n")) {
     textContent = textContent.slice(0, -1)
  }
  return textContent
}

const addCopyButtonToCodeCells = () => {
  // If ClipboardJS hasn't loaded, wait a bit and try again. This
  // happens because we load ClipboardJS asynchronously.
  if (window.ClipboardJS === undefined) {
    setTimeout(addCopyButtonToCodeCells, 250)
    return
  }

  // Add copybuttons to all of our code cells
  const codeCells = document.querySelectorAll('div.highlight pre')
  codeCells.forEach((codeCell, index) => {
    const id = codeCellId(index)
    codeCell.setAttribute('id', id)
    const pre_bg = getComputedStyle(codeCell).backgroundColor;

    const clipboardButton = id =>
    `<a class="copybtn o-tooltip--left" style="background-color: ${pre_bg}" data-tooltip="${messages[locale]['copy']}" data-clipboard-target="#${id}">
      <img src="${DOCUMENTATION_OPTIONS.URL_ROOT}_static/copy-button.svg" alt="${messages[locale]['copy_to_clipboard']}">
    </a>`
    codeCell.insertAdjacentHTML('afterend', clipboardButton(id))
  })

  // Initialize with a callback so we can modify the text before copy
  const clipboard = new ClipboardJS('.copybtn', {text: copyTargetText})

  // Update UI with error/success messages
  clipboard.on('success', event => {
    clearSelection()
    temporarilyChangeTooltip(event.trigger, messages[locale]['copy_success'])
  })

  clipboard.on('error', event => {
    temporarilyChangeTooltip(event.trigger, messages[locale]['copy_failure'])
  })
}

runWhenDOMLoaded(addCopyButtonToCodeCells)