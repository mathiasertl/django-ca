django.jQuery(document).ready(function() {
    var ca_details;
    var ca_details_selector = '.field-ca select'
    var ca_details_url = django.jQuery('meta[name="ca-details-url"]').attr('value');

    django.jQuery.get(ca_details_url).done(function(data) {
        ca_details = data;

        // set the "fetched" property, this can be used by selenium tests to wait until this API has returned
        django.jQuery('meta[name="ca-details-url"]').attr('fetched', "true");
    });


    // This should be set in the form via intial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery(ca_details_selector).change(function() {
        ca_config = ca_details[this.value];
        if (typeof ca_config === 'undefined') {
            return;
        }
        var extensions = ca_config.extensions;

        if (typeof extensions.issuer_alternative_name !== 'undefined') {
            var value = extensions.issuer_alternative_name.value.join("\n");
            django.jQuery('.field-issuer_alternative_name textarea').val(value);
        }
        if (typeof extensions.authority_information_access !== 'undefined') {
            var aia = extensions.authority_information_access;
            if (typeof aia.value.issuers !== 'undefined') {
                django.jQuery('textarea#id_authority_information_access_0').val(aia.value.issuers.join('\n'));
            }
            if (typeof aia.value.ocsp !== 'undefined') {
                django.jQuery('textarea#id_authority_information_access_1').val(aia.value.ocsp.join('\n'));
            }
        }
        if (typeof extensions.crl_distribution_points !== 'undefined') {
            var dpoint = extensions.crl_distribution_points.value[0];
            if (typeof dpoint.full_name !== 'undefined') {
                django.jQuery('textarea#id_crl_distribution_points_0').val(dpoint.full_name.join('\n'));
            }
        }
    });
});
