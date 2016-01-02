django.jQuery(document).ready(function() {
    var profile_selector = '.field-profile select'

    // This should be set in the form via intial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery(profile_selector).change(function() {
        if (this.value == '') {
            return;  // do nothing if we don't select a profile
        }

        profile = ca_profiles[this.value];
        console.log(profile);
        extensions = ['basicConstraints', 'keyUsage', 'extendedKeyUsage']
        extensions.map(function(ext) {
            var critical_selector = '.field-' + ext + ' .critical-widget-wrapper input';
            django.jQuery(critical_selector).prop('checked', profile[ext].critical);
            var value_selector = '.field-' + ext + ' select';
            django.jQuery(value_selector).val(profile[ext].value);
        });
    });
});
