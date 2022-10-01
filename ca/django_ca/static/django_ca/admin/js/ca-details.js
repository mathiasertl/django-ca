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
        if (typeof ca_config.issuer_alternative_name !== 'undefined') {
            django.jQuery('.field-issuer_alternative_name textarea').val(ca_config.issuer_alternative_name);
        }
});
