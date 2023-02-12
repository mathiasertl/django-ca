django.jQuery(document).ready(function() {
    var ca_details;
    var ca_details_selector = '.field-ca select'
    var ca_details_url = django.jQuery('meta[name="ca-details-url"]').attr('content');

    django.jQuery.get(ca_details_url).done(function(data) {
        ca_details = data;

        // set the "fetched" property, this can be used by selenium tests to wait until this API has returned
        django.jQuery('meta[name="ca-details-url"]').attr('fetched', "true");
    });


    // This should be set in the form via initial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery(ca_details_selector).change(function() {
        ca_config = ca_details[this.value];
        if (typeof ca_config === 'undefined') {
            return;
        }
        var extensions = ca_config.extensions;
        update_extensions(extensions);

        // set the signature hash algorithm
        var hash_algorithm_select = django.jQuery('select#id_algorithm');
        if (ca_config.signature_hash_algorithm === null) {
            hash_algorithm_select.val('');
        } else {
            hash_algorithm_select.val(ca_config.signature_hash_algorithm);
        }
    });
});
