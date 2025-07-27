/**
 * Functions for handling extensions in the add-certificate admin form.
 */

/**
 * Clear extensions with the given extension keys.
 */
const clear_extensions = function(extensions) {
    if (typeof extensions === "undefined" || typeof extensions !== 'object') {
        console.error("clear_extensions() received invalid object:", typeof extensions)
        return;
    };

    Object.entries(extensions).forEach((ext) => {
        const [key, value] = ext;

        // Check if extension is configured to be cleared...
        if (value !== null) {
            return;  // ... it is not.
        }
        let field = document.querySelector(".form-row.field-" + key);

        // Unset critical flag
        field.querySelector('.labeled-checkbox.critical input').checked = false;

        if (['extended_key_usage', 'key_usage', 'tls_feature'].includes(key)) {
            set_select_multiple(field.querySelector("select"), []);
        } else if (['crl_distribution_points', 'freshest_crl'].includes(key)) {
            field.querySelectorAll('.key-value-list button.remove-row-btn').forEach((elem) => {
                elem.click();
            });
            field.querySelector('input.relative-name').value = "";
            set_select_multiple(field.querySelector('select.reasons'), []);
        } else if (['issuer_alternative_name', 'subject_alternative_name'].includes(key)) {
            field.querySelectorAll('.key-value-list button.remove-row-btn').forEach((elem) => {
                elem.click();
            });
        } else if (key === "authority_information_access") {
            field.querySelectorAll('.key-value-list button.remove-row-btn').forEach((elem) => {
                elem.click();
            });
        } else if (key === "certificate_policies") {
            field.querySelector('input#id_' + key + '_0').value = "";
            field.querySelector('textarea#id_' + key + '_1').value = "";
            field.querySelector('textarea#id_' + key + '_2').value = "";
        } else if (key === "ocsp_no_check") {
            field.querySelector('.labeled-checkbox.include input').checked = false;
        } else {
            console.log("Unknown extension type to clear:", ext);
        }
    });
};


/**
 * Update given extensions.
 */
const update_extensions = async function(extensions) {
    if (typeof extensions === "undefined" || typeof extensions !== 'object') {
        console.error("clear_extensions() received invalid object:", typeof extensions)
        return;
    };

    Object.entries(extensions).forEach(async (entry) => {
        const [key, ext] = entry;

        // If extension value is null, it is handled by clear_extensions()
        if (ext === null) {
            return;
        }

        let field = document.querySelector(".form-row.field-" + ext.type);

        // profile serialization will make sure that any not-null extension will have a critical value
        field.querySelector('.labeled-checkbox.critical input').checked = ext.critical;
        console.log('Updating ' + ext.type);

        if (['extended_key_usage', 'key_usage', 'tls_feature'].includes(ext.type)) {
            set_select_multiple(field.querySelector("select"), ext.value);
        } else if (['crl_distribution_points', 'freshest_crl'].includes(ext.type)) {
            let dpoint = ext.value[0];

            // get respective key-value fields
            let full_name_field = field.querySelector('.key-value-field-crl_distribution_points_0');
            let crl_issuer_field = field.querySelector('.key-value-field-crl_distribution_points_2');

            // Get respective add buttons
            let full_name_add_btn = full_name_field.querySelector('button.add-row-btn');
            let crl_issuer_field_add_btn = crl_issuer_field.querySelector('button.add-row-btn');

            // Update full name rows
            if (dpoint.full_name) {
                dpoint.full_name.forEach((general_name) => {
                    full_name_add_btn.click();
                    let last_row = full_name_field.querySelector('.key-value-list div:last-of-type');
                    last_row.querySelector('select').value = general_name.type;
                    last_row.querySelector('input').value = general_name.value;
                });
            }

            // Update relative name
            let relative_name = "";
            if (dpoint.relative_name) {
                relative_name = await name_to_rfc4514(dpoint.relative_name);
            }
            field.querySelector('input#id_' + ext.type + '_1').value = relative_name;

            // Update CRL issuer rows
            if (dpoint.crl_issuer) {
                dpoint.crl_issuer.forEach((general_name) => {
                    crl_issuer_field_add_btn.click();
                    let last_row = crl_issuer_field.querySelector('.key-value-list div:last-of-type');
                    last_row.querySelector('select').value = general_name.type;
                    last_row.querySelector('input').value = general_name.value;
                });
            }

            // Update reasons
            let reasons = dpoint.reasons ? dpoint.reasons : [];
            set_select_multiple(field.querySelector('select#id_' + ext.type + '_3'), reasons);
        } else if (['issuer_alternative_name', 'subject_alternative_name'].includes(ext.type)) {
            console.log(ext.value);
            let add_btn = field.querySelector('button.add-row-btn');
            ext.value.forEach((general_name) => {
                add_btn.click();
                let last_row = field.querySelector('.key-value-list div:last-of-type');
                last_row.querySelector('select').value = general_name.type;
                last_row.querySelector('input').value = general_name.value;
            });
        } else if (ext.type === "authority_information_access") {
            // group AccessDescriptions by AccessMethod
            let ca_issuers_ad = ext.value.filter(gn => gn.access_method === '1.3.6.1.5.5.7.48.2');
            let ocsp_ad = ext.value.filter(gn => gn.access_method === '1.3.6.1.5.5.7.48.1');

            // Get AccessLocation objects
            let ca_issuer_names = ca_issuers_ad.map(ad => ad.access_location);
            let ocsp_names = ocsp_ad.map(ad => ad.access_location);

            // Get sub-chapters for types (to shorten queries)
            let ca_issuer_widget = field.querySelector('.key-value-field-authority_information_access_0');
            let ocsp_widget = field.querySelector('.key-value-field-authority_information_access_1');

            // Get add buttons
            let ca_issuer_add_btn = ca_issuer_widget.querySelector('button.add-row-btn');
            let ocsp_add_btn = ocsp_widget.querySelector('button.add-row-btn');

            // Update CA issuer rows
            ca_issuer_names.forEach((access_location) => {
                ca_issuer_add_btn.click();
                let last_row = ca_issuer_widget.querySelector('.key-value-list div:last-of-type');
                last_row.querySelector('select').value = access_location.type;
                last_row.querySelector('input').value = access_location.value;
            });

            // Update OCSP rows
            ocsp_names.forEach((access_location) => {
                ocsp_add_btn.click();
                let last_row = ocsp_widget.querySelector('.key-value-list div:last-of-type');
                last_row.querySelector('select').value = access_location.type;
                last_row.querySelector('input').value = access_location.value;
            });
        } else if (ext.type === "certificate_policies") {
            // We only support one policy information object, return if there are more
            if (ext.value.length > 1) {
                return;
            }
            let policy_information = ext.value[0];

            // set policy identifier
            field.querySelector('input#id_' + ext.type + '_0').value = policy_information.policy_identifier;

            let cps = [];
            let explicit_text = "";

            // support for policy qualifiers is currently extremely limited. We map all str qualifiers into
            // a newline-separated list, and use the first explicit text defined in any user notice.
            if (policy_information.policy_qualifiers) {
                policy_information.policy_qualifiers.map(qualifier => {
                    if (typeof qualifier == "string") {
                        cps.push(qualifier);
                    } else if (explicit_text == "" && qualifier.explicit_text) {
                        explicit_text = qualifier.explicit_text;
                    }
                });
            }

            field.querySelector('textarea#id_' + ext.type + '_1').value = cps.join("\n");
            field.querySelector('textarea#id_' + ext.type + '_2').value = explicit_text;
        } else if (ext.type === "ocsp_no_check") {
            field.querySelector('.labeled-checkbox.include input').checked = true;
        } else {
            console.log("Unknown extension type to update:", ext);
        }
    });
};
