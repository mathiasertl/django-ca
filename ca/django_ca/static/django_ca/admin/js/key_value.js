/**
 * Update the hidden input field with the values from the key/value form
 */
function updateJsonValueField(field) {
    var list = field.querySelector('.key-value-list');
    var inputField = field.querySelector("input[type='hidden']");

    // collect current data from input row
    var data = [];
    list.querySelectorAll(".key-value-row").forEach((row) => {
        var row_key = row.querySelector('select.key-value-input').value;
        var row_value = row.querySelector('input.key-value-input').value.trim();

        // Only add value if there is a text value entered
        if (row_key && row_value) {
            data.push({
                key: row_key,
                value: row_value
            });
        }
    });

    // Finally update the field (only if it has changed)
    var final_value = JSON.stringify(data);
    if (final_value !== inputField.value) {
        inputField.value = final_value;

        // Fire change event so that other libraries can listen to modifications
        inputField.dispatchEvent(new Event('change'));
    }
}

/**
 * Add the passed event listener to all modifications of the passed row.
 */
function addRowUpdateEventListeners(row, listener) {
    row.querySelector("select.key-value-input").addEventListener("change", listener);
    row.querySelector("input.key-value-input").addEventListener("input", listener);
    row.querySelector("button.remove-row-btn").addEventListener("click", listener);
}

/**
 * Append a new row to the key/value form of the given field.
 */
function appendKeyValueRow(field, key, value) {
    var template = field.querySelector('.key-value-row');
    var list = field.querySelector('.key-value-list');
    var row = template.cloneNode(true);

    // Set any value if passed (happens during page load)
    row.querySelector('select.key-value-input').value = key ? key : "";
    row.querySelector('input.key-value-input').value = value ? value : "";

    row.querySelector('button.remove-row-btn').addEventListener("click", (event) => {
        row.remove();
    });
    addRowUpdateEventListeners(row, (event) => {
        updateJsonValueField(field);
    });

    // Finally, append the row
    list.insertBefore(row, null);
    return row;
}

/**
 * Load the JSON data from the hidden input field into the key/value form of the passed field.
 */
function loadKeyValueList(field, inputValue) {
    // Do nothing if we get an empty JSON list
    if (! inputValue) {
        return;
    }
    field.querySelector('.key-value-list').innerHTML = "";

    // Add a row for each name attribute in the hidden input field
    inputValue.forEach((name_attr) => {
        appendKeyValueRow(field, name_attr.key, name_attr.value);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    // set up each key/value field
    document.querySelectorAll('div.key-value-field').forEach((field) => {
        // populate with any existing value on load
        var inputField = field.querySelector("input[type='hidden']");
        if (inputField && inputField.value) {
            let inputValue = JSON.parse(inputField.value);
            loadKeyValueList(field, inputValue);
        }

        // Key/value form
        const keyValuePairList = field.querySelector('.key-value-list');

        // "global" element of the handle of the currently dragged row.
        let draggingElement = null;

        // Called when starting to drag.
        keyValuePairList.addEventListener('dragstart', (event) => {
            draggingElement = event.target.querySelector('.draggable-handle');

            // CSS class to update the mouse cursor
            draggingElement.classList.add('dragging');
        });

        // A row is being dragged over another row, event.target is the row that is being dragged over.
        keyValuePairList.addEventListener('dragover', (event) => {
            event.preventDefault();
            const targetRow = event.target.closest('.key-value-row');
            const draggedRow = draggingElement.closest('.key-value-row');

            if (targetRow && targetRow !== draggedRow) {
                targetRow.classList.add('drop-target');
            }
        });

        // The dragged row is "leaving" a row, event.target is the row that was being dragged over.
        keyValuePairList.addEventListener('dragleave', (event) => {
            const targetRow = event.target.closest('.key-value-row');
            if (targetRow) {
                targetRow.classList.remove('drop-target');
            }
        });

        // Drop a row at the new desired position.
        keyValuePairList.addEventListener('drop', (event) => {
            event.preventDefault();
            const targetRow = event.target.closest('.key-value-row');
            const draggedRow = draggingElement.closest('.key-value-row');

            if (targetRow && targetRow !== draggedRow) {
                targetRow.parentNode.insertBefore(draggedRow, targetRow.nextSibling);
            }

            // update data when re-arranging order
            updateJsonValueField(field);

            // Fire custom event that the user re-ordered rows
            field.dispatchEvent(new CustomEvent("userReordersKeyValueRow", {detail: field}));

            // reset row over which the row was dropped
            targetRow.classList.remove("drop-target");

            // reset dragging handle
            draggingElement.classList.remove('dragging');
            draggingElement = null;
        });

        // add draggable handle over every draggable handle
        field.querySelectorAll('.key-value-list .draggable-handle').forEach((handle) => {
            handle.addEventListener('click', (event) => {
                const listItem = event.target.closest('.key-value-row');
                listItem.dispatchEvent(new Event('dragstart', { bubbles: true }));
            });
        });

        // Add event listener for the Add button
        const addRowButtons = field.querySelectorAll('button.add-row-btn');
        addRowButtons.forEach((handle) => {
            handle.addEventListener('click', (event) => {
                let row = appendKeyValueRow(field);

                // fire event that the user added a row
                field.dispatchEvent(new CustomEvent("userAddsKeyValueRow", {detail: row}));
            });
        });
    });
});