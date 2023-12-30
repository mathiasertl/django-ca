/**
 * Asynchronous post request with given url and JSON body.
 *
 * *body* might be any object that can be passed to JSON.stringify().
 *
 * The function returns the HTTP response object.
 */
const async_post = async function(url, body) {
    // get CSRF token
    const csrftoken = document.querySelector('body input[name=csrfmiddlewaretoken]').value;

    // Convert to RFC 4514 string via API call
    let response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrftoken
        },
        body: JSON.stringify(body),
    });
    return response;
};

/**
 * Set multiple options on the given select field.
 */
const set_select_multiple = function(select, selected) {
    [...select.options].map(opt => opt.selected = selected.includes(opt.value));
};

/**
 * Convert serialized name to RFC4514 representation via asynchronous HTTP request.
 */
const name_to_rfc4514 = async function(name) {
    url = document.querySelector("head meta[name=name-to-rfc4514-url]").content;
    const response = await async_post(url, name);
    const parsed_response = await response.json();
    return parsed_response.name;
};

/**
 * Convert general name to string.
 */
const general_name_to_string = function(general_name) {
    return general_name.type + ":" + general_name.value;
}

/**
 * Convert array of general names to newline-separated string.
 */
const general_names_to_string = function(general_names) {
    return general_names.map(general_name => general_name_to_string(general_name)).join("\n");
};