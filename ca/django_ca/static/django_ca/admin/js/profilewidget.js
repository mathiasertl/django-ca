django.jQuery(document).ready(function() {
    var profile_selector = '.field-profile select'

    // This should be set in the form via intial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery(profile_selector).change(function() {
        if (this.value == '') {
            django.jQuery('.field-profile .profile-desc').hide();
            return;  // do nothing if we don't select a profile
        }

        profile = ca_profiles[this.value];
        // update extensions
        extensions = ['basicConstraints', 'keyUsage', 'extendedKeyUsage']
        extensions.map(function(ext) {
            var critical_selector = '.field-' + ext + ' .critical-widget-wrapper input';
            var value_selector = '.field-' + ext + ' select';
            if (profile[ext] == null) {
                // the extension may be null, meaning the extension should not be added
                django.jQuery(critical_selector).prop('checked', false);
                django.jQuery(value_selector).val([]);
                django.jQuery(value_selector).change();  // so any existing callbacks are called
            } else {
                django.jQuery(critical_selector).prop('checked', profile[ext].critical);
                django.jQuery(value_selector).val(profile[ext].value);
                django.jQuery(value_selector).change();  // so any existing callbacks are called
            }
        });

        // update description
        django.jQuery('.field-profile .profile-desc').show();
        django.jQuery('.field-profile .profile-desc').text(profile.desc);
    });
});
