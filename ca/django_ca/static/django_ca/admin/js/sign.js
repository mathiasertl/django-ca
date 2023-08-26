// see https://docs.djangoproject.com/en/dev/ref/csrf/#ajax
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = django.jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
var csrftoken = getCookie('csrftoken');

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
django.jQuery.ajaxSetup({
    beforeSend: function(xhr, settings) {
        var token = csrftoken ? csrftoken : document.querySelector('[name=csrfmiddlewaretoken]').value;
        if (!csrfSafeMethod(settings.type) && !this.crossDomain && token) {
            xhr.setRequestHeader("X-CSRFToken", token);
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    var csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    var csr_details_url = document.querySelector('meta[name="csr-details-url"]').getAttribute('content');

    // global for the subject field
    var subject_field = document.querySelector('.field-subject .key-value-field');
    var subject_input = subject_field.querySelector('input#id_subject_0');  // actual hidden input
    var key_value_list = subject_field.querySelector('.key-value-list');
    var csr_subject_input_chapter = subject_field.querySelector(".subject-input-chapter.csr");
    var profile_subject_input_chapter = subject_field.querySelector(".subject-input-chapter.profile");
    var profile_select = document.querySelector(".field-profile select");
    var profile_data = JSON.parse(document.getElementById("profile-data").textContent);
    var oid_names = JSON.parse(document.getElementById("oid-names").textContent);

    // Shortcut for a JSON POST request with JSON response. Returns promise for JSON.
    async function post(url, body) {
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
     * Set up listeners on key, value and remove that adds the modified flag on any update.
     */
    function addModifiedEventListeners(row) {
        addRowUpdateEventListeners(row, (event) => {
            subject_field.dataset.modified = "true";
        });
    };

    /**
     * Call addModifiedEventListeners() for all rows in the key/value list.
     */
    function addModifiedEventListenersToAllRows() {
        key_value_list.querySelectorAll(".key-value-row").forEach((row) => {
            addModifiedEventListeners(row);
        });
    }

    /**
     * Set up a subject input chapter with copy/clear buttons.
     */
    function setupSubjectInputChapter(subject_input_chapter) {
        subject_input_chapter.querySelector(".copy-button").addEventListener("click", (event) => {
            var data = JSON.parse(subject_input_chapter.dataset.value);

            loadKeyValueList(subject_field, data);  // update normal input fields
            updateJsonValueField(subject_field);  // update hidden input field
            addModifiedEventListenersToAllRows();
        });

        subject_input_chapter.querySelector(".clear-button").addEventListener("click", (event) => {
            key_value_list.innerHTML = "";
            subject_input.value = "[]";
        });
    }

    /**
     * load given data into the given subject input chapter.
     */
    function loadDataToSubjectInputChapter(subject_input_chapter, data) {
        var ul = subject_input_chapter.querySelector("ul")

        // clear the list (will be populated with data below).
        ul.innerHTML = "";

        // set JSON data in data-value attribute
        subject_input_chapter.dataset.value = JSON.stringify(data);

        if (data.length > 0) {
            var li_template = subject_field.querySelector(".subject-input-element-template");

            // Append a row for each key/value pair based on the template
            data.forEach((obj) => {
                var li_node = li_template.content.cloneNode(true);
                li_node.querySelector(".oid").textContent = oid_names[obj.key];
                li_node.querySelector(".value").textContent = obj.value;

                ul.insertBefore(li_node, null);
            });

            subject_input_chapter.querySelector('.has-content').style.display = 'block';
            subject_input_chapter.querySelector('.no-content').style.display = 'none';
        } else {
            subject_input_chapter.querySelector('.has-content').style.display = 'none';
            subject_input_chapter.querySelector('.no-content').style.display = 'block';
        }
    }

    // When the user adds a row, call addModifiedEventListeners
    subject_field.addEventListener("userAddsKeyValueRow", (event) => {
        // NOTE: Do not set the modified flag here, as a new row has no value, and rows with no value are not
        // added to the subject. So a new row does not yet modify the subject.
        addModifiedEventListeners(event.detail);
    });

    // When the user re-orders rows, also set the "modified" flag
    subject_field.addEventListener("userReordersKeyValueRow", (event) => {
        subject_field.dataset.modified = "true";
    });

    // Set up any initially loaded subject input chapters
    subject_field.querySelectorAll(".subject-input-chapter").forEach((subject_input_chapter) => {
        setupSubjectInputChapter(subject_input_chapter);
    });

    // Set up the profile input field
    profile_select.addEventListener("change", (event) => {
        var value = event.target.value;
        var profile_subject = profile_data[value].subject;

        if (profile_subject) {
            profile_subject = profile_subject.map(({oid: key, value}) => ({value, key}));
        } else {
            profile_subject = []
        }

        // if the subject field was not yet modified, also set the subject based on the profile
        if (subject_field.dataset.modified !== "true") {
            subject_input.value = "[]";

            if (profile_subject.length > 0) {
                loadKeyValueList(subject_field, profile_subject);  // update normal input fields
                updateJsonValueField(subject_field);  // update hidden input field
                addModifiedEventListenersToAllRows();
            } else {
                key_value_list.innerHTML = "";
            }
        }
        loadDataToSubjectInputChapter(profile_subject_input_chapter, profile_subject);
    });

    // Set up the CSR input field
    var csr_textarea = document.querySelector('.field-csr textarea');
    if (csr_textarea) { // not set on the resign form
        document.querySelector('.field-csr textarea').addEventListener('input', async (event) => {
            // No data is fetched yet
            event.target.dataset.fetched = "false"

            var input = event.target;
            var value = input.value.trim();

            // check if this at least *appears* to be a CSR by checking the delimiters
            if (! (value.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')
                   && value.endsWith('\n-----END CERTIFICATE REQUEST-----'))) {
                csr_subject_input_chapter.querySelector(".no-csr").style.display = "block";
                csr_subject_input_chapter.querySelector(".has-content").style.display = "none";
                csr_subject_input_chapter.querySelector(".no-content").style.display = "none";
                return;
            }

            // Retrieve CSR data via API
            const csr_response = await post(csr_details_url, {csr: value});
            if (csr_response.status !== 200) {
                csr_subject_input_chapter.querySelector(".no-csr").style.display = "block";
                csr_subject_input_chapter.querySelector(".has-content").style.display = "none";
                csr_subject_input_chapter.querySelector(".no-content").style.display = "none";
                return;
            }
            const csr_data = await csr_response.json();
            const subject = csr_data["subject"];


            // No need to do anything if the CSR has an empty subject
            if (subject.length === 0) {
                csr_subject_input_chapter.querySelector(".no-csr").style.display = "none";
                csr_subject_input_chapter.querySelector(".has-content").style.display = "none";
                csr_subject_input_chapter.querySelector(".no-content").style.display = "block";

                // Set the data-fetched property, so that Selenium tests can wait for completion.
                input.dataset.fetched = "true"
                return;
            }

            loadDataToSubjectInputChapter(csr_subject_input_chapter, subject);
            csr_subject_input_chapter.querySelector(".no-csr").style.display = "none";
            csr_subject_input_chapter.querySelector(".has-content").style.display = "block";
            csr_subject_input_chapter.querySelector(".no-content").style.display = "none";

            // Set the data-fetched property, so that Selenium tests can wait for completion.
            input.dataset.fetched = "true"
        });
    }

    // Add listener for all rows loaded on initial page load
    addModifiedEventListenersToAllRows();

    // Load the initial data into the profile subject input chapter
    if (profile_data[profile_select.value].subject) {
        loadDataToSubjectInputChapter(
            profile_subject_input_chapter,
            profile_data[profile_select.value].subject.map(({oid: key, value}) => ({value, key}))
        );
    } else {
        loadDataToSubjectInputChapter(profile_subject_input_chapter, []);
    }

    // If you copy the full subject from the profile, it is again "not modified" by definition
    profile_subject_input_chapter.querySelectorAll(".inline-text-button").forEach((button) => {
        button.addEventListener("click", (event) => {
            console.log('click on profile!');
            subject_field.dataset.modified = "false";
        });
    });

    // But if you copy from the CSR, it is modified by definition
    csr_subject_input_chapter.querySelectorAll(".inline-text-button").forEach((button) => {
        button.addEventListener("click", (event) => {
            console.log('click on csr??');
            subject_field.dataset.modified = "true";
        });
    });
});