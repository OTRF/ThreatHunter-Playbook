/**
 * Select various elements on the page for later use
 */

// IDs we'll attach to cells
const codeCellId = index => `codecell${index}`
const inputCellId = index => `inputcell${index}`

pageElements = {}

// All code cells
findCodeCells = function() {
    var codeCells = document.querySelectorAll('div.c-textbook__content > div.highlighter-rouge > div.highlight > pre, div.input_area pre, div.text_cell_render div.highlight pre')
    pageElements['codeCells'] = codeCells;

    codeCells.forEach((codeCell, index) => {
      const id = codeCellId(index)
      codeCell.setAttribute('id', id)
    })
};

initFunction(findCodeCells);

// All cells in general
findInputCells = function() {
    var inputCells = document.querySelectorAll('div.jb_cell')
    pageElements['inputCells'] = inputCells;

    inputCells.forEach((inputCell, index) => {
        const id = inputCellId(index)
        inputCell.setAttribute('id', id)
    })
};

initFunction(findInputCells);