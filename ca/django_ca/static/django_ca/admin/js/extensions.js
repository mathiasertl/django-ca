var update_extensions = function(extensions) {
    if (typeof extensions === 'undefined') {
        return;
    };
    django.jQuery.each(extensions, function(key, ext) {
        if (ext === null) {
            return;
        };

        // form-row containing the extension
		var field = django.jQuery('.form-row.field-' + key);

		// profile serialization will make sure that any not-null extension will have a critical value
		field.find('.labeled-checkbox.critical input').prop('checked', ext.critical === true);

		// handle "multiple choice" extensions
        if (['extended_key_usage', 'key_usage', 'tls_feature'].includes(key)) {
			if (ext == null) {
				field.find('select').val([]);
			} else {
				field.find('select').val(ext.value);
			}
			field.find('select').change();  // so any existing callbacks are called
		} else if (key === "certificate_policies") {
		    // We only support one policy information object, return if there are more
		    if (ext.value.length > 1) {
		        return;
		    }
		    var policy_information = ext.value[0];
		    var cps = [];
		    var explicit_text = "";

		    for (policy_qualifier of policy_information.policy_qualifiers) {
		        if (typeof policy_qualifier == "string") {
		            cps.push(policy_qualifier);
		        } else {
                    if (policy_qualifier.notice_reference) {
                        return;  // We don't support notice references
                    } else if (explicit_text == "") {
		                explicit_text = policy_qualifier.explicit_text;
		            } else {
		                return;  // extension has more then one explicit text
		            }
		        }
		    }

		    field.find('input#id_' + key + '_0').val(policy_information.policy_identifier);
		    field.find('textarea#id_' + key + '_1').val(cps.join("\n"));
		    field.find('textarea#id_' + key + '_2').val(explicit_text);
        } else if (key === 'crl_distribution_points' || key === 'freshest_crl') {
            var dpoint = ext.value[0];
            var full_name = dpoint.full_name ? dpoint.full_name.join('\n') : "";
            var relative_name = dpoint.relative_name ? dpoint.relative_name : "";
            var crl_issuer = dpoint.crl_issuer ? dpoint.crl_issuer.join('\n') : "";
            var reasons = dpoint.reasons ? dpoint.reasons : [];

            field.find('textarea#id_' + key + '_0').val(full_name);
            field.find('input#id_' + key + '_1').val(relative_name);
            field.find('textarea#id_' + key + '_2').val(crl_issuer);
            field.find('select#id_' + key + '_3').val(reasons);
		} else if (key === "authority_information_access") {
            var issuers = ext.value.issuers ? ext.value.issuers.join("\n") : "";
            var ocsp = ext.value.ocsp ? ext.value.ocsp.join("\n") : "";

            field.find('textarea.ca-issuers').val(issuers);
            field.find('textarea.ocsp').val(ocsp);
        } else if (key === 'ocsp_no_check') {
			field.find('.labeled-checkbox.include input').prop('checked', ext !== null);
			field.find('.labeled-checkbox.include input').change();  // so any existing callbacks are called
        } else if (key === 'issuer_alternative_name') {
            var names = ext.value ? ext.value.join('\n') : "";
            field.find('textarea').val(names);
		} else {
			console.log("Unhandled extension: " + key);
		}

    });
};
