django.jQuery(document).ready(function() {
    var ca_selector = '.field-basicConstraints #id_basicConstraints_0'
    var ca_initial_value = django.jQuery(ca_selector).val();
    if (ca_initial_value == 'CA:FALSE') {
        django.jQuery('.field-basicConstraints .pathlen-widget-wrapper').hide();
    }

    django.jQuery(ca_selector).change(function() {
        if (this.value == 'CA:TRUE') {
            django.jQuery('.field-basicConstraints .pathlen-widget-wrapper').show();
        } else {
            django.jQuery('.field-basicConstraints .pathlen-widget-wrapper').hide();
        }
    });
});
