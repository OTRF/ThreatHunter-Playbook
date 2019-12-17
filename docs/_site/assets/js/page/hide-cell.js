/**
  Add buttons to hide code cells
*/
var setCellVisibility = function (inputField, kind) {
    // Update the image and class for hidden
    var id = inputField.getAttribute('data-id');
    var element = document.querySelector(`#${id}`);

    if (kind === "visible") {
        element.classList.remove('hidden');
        inputField.checked = true;
    } else {
        element.classList.add('hidden');
        inputField.checked = false;
    }
}

var toggleCellVisibility = function (event) {
    // The label is clicked, and now we decide what to do based on the input field's clicked status
    if (event.target.tagName === "LABEL") {
        var inputField = event.target.previousElementSibling;
    } else {
        // It is the span inside the target
        var inputField = event.target.parentElement.previousElementSibling;
    }

    if (inputField.checked === true) {
        setCellVisibility(inputField, "visible");
    } else {
        setCellVisibility(inputField, "hidden");
    }
}


// Button constructor
const hideCodeButton = id => `<input class="hidebtn" type="checkbox" id="hidebtn${id}" data-id="${id}"><label title="Toggle cell" for="hidebtn${id}" class="plusminus"><span class="pm_h"></span><span class="pm_v"></span></label>`

var addHideButton = (element, id) => {
    // Add a hide button to an HTML element.
    element.setAttribute("id", id)
    // Insert the button just inside the end of the next div
    element.insertAdjacentHTML('afterend', hideCodeButton(id))

    // Set up the visibility toggle
    // The label will be two-sibings deep from the element to-be hidden
    hideLink = element.nextElementSibling.nextElementSibling;
    hideLink.addEventListener('click', toggleCellVisibility)
}

var addAllHideButtons = function () {
    // If a hide button is already added, don't add another
    if (document.querySelector('input.hidebtn') !== null) {
        return;
    }

    // Find the input cells and add a hide button
    hideIdNum = 0;
    pageElements['inputCells'].forEach((cell) => {
        const id = cell.getAttribute('id')

        if (cell.classList.contains("tag_hide_input")) {
            addHideButton(cell.querySelector('div.inner_cell'), `hide-${hideIdNum}`);
            hideIdNum ++;
        }

        if (cell.classList.contains("tag_hide_output")) {
            addHideButton(cell.querySelector('div.output'), `hide-${hideIdNum}`);
            hideIdNum ++;
        }
    });
}


// Initialize the hide buttos
var initHiddenCells = function () {
    // Add hide buttons to the cells
    addAllHideButtons();

    // Toggle the code cells that should be hidden
    document.querySelectorAll('div.tag_hide_input input, div.tag_hide_output input').forEach(function (item) {
        setCellVisibility(item, 'hidden');
        item.checked = true;
    })
}

initFunction(initHiddenCells);