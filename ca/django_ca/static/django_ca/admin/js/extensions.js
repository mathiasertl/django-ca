/**
 * Functions for handling extensions in the add-certificate admin form.
 */

/**
 * Clear extensions with the given extension keys.
 */
const clear_extensions = function(extension_keys) {
    extension_keys.forEach((key) => {
        let field = document.querySelector(".form-row.field-" + key);

        // Unset critical flag
		field.querySelector('.labeled-checkbox.critical input').checked = false;

		if (['extended_key_usage', 'key_usage', 'tls_feature'].includes(key)) {
            set_select_multiple(field.querySelector("select"), []);
        } else if (['crl_distribution_points', 'freshest_crl'].includes(key)) {
            field.querySelector('textarea#id_' + key + '_0').value = "";
            field.querySelector('input#id_' + key + '_1').value = "";
            field.querySelector('textarea#id_' + key + '_2').value = "";

            set_select_multiple(field.querySelector('select#id_' + key + '_3'), []);
        } else if (['issuer_alternative_name', 'subject_alternative_name'].includes(key)) {
            field.querySelector('textarea#id_' + key + '_0').value = "";
        } else if (key === "authority_information_access") {
            field.querySelector('textarea#id_' + key + '_0').value = "";
            field.querySelector('textarea#id_' + key + '_1').value = "";
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
    if (typeof extensions === "undefined" || ! Array.isArray(extensions)) {
        return;
    };

    extensions.forEach(async (ext) => {
        let field = document.querySelector(".form-row.field-" + ext.type);

        // profile serialization will make sure that any not-null extension will have a critical value
		field.querySelector('.labeled-checkbox.critical input').checked = ext.critical;

        if (['extended_key_usage', 'key_usage', 'tls_feature'].includes(ext.type)) {
            set_select_multiple(field.querySelector("select"), ext.value);
        } else if (['crl_distribution_points', 'freshest_crl'].includes(ext.type)) {
            let dpoint = ext.value[0];
            let full_name = dpoint.full_name ? general_names_to_string(dpoint.full_name) : "";

            let relative_name = "";
            if (dpoint.relative_name) {
                relative_name = await name_to_rfc4514(dpoint.relative_name);
            }

            let crl_issuer = dpoint.crl_issuer ? general_names_to_string(dpoint.crl_issuer) : "";
            let reasons = dpoint.reasons ? dpoint.reasons : [];

            field.querySelector('textarea#id_' + ext.type + '_0').value = full_name;
            field.querySelector('input#id_' + ext.type + '_1').value = relative_name;
            field.querySelector('textarea#id_' + ext.type + '_2').value = crl_issuer;

            set_select_multiple(field.querySelector('select#id_' + ext.type + '_3'), reasons);
        } else if (['issuer_alternative_name', 'subject_alternative_name'].includes(ext.type)) {
            field.querySelector('textarea#id_' + ext.type + '_0').value = general_names_to_string(ext.value);
        } else if (ext.type === "authority_information_access") {
            // group access descriptions by type
            let ca_issuers_ad = ext.value.filter(gn => gn.access_method === "1.3.6.1.5.5.7.48.2");
            let ocsp_ad = ext.value.filter(gn => gn.access_method === "1.3.6.1.5.5.7.48.1");

            // get list of general names for each type
            let ca_issuer_names = ca_issuers_ad.map(ad => ad.access_location);
            let ocsp_names = ocsp_ad.map(ad => ad.access_location);

            // format to newline-separated string
            let ca_issuers = general_names_to_string(ca_issuer_names);
            let ocsp = general_names_to_string(ocsp_names);

            field.querySelector('textarea#id_' + ext.type + '_0').value = ca_issuers;
            field.querySelector('textarea#id_' + ext.type + '_1').value = ocsp;
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
