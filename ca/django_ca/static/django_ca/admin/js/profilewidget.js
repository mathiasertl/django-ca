django.jQuery(document).ready(function() {
    var ca_profiles;
    var profile_selector = '.field-profile select'
    var profile_url = django.jQuery('meta[name="get-profiles-url"]').attr('value');

    django.jQuery.get(profile_url).done(function(data) {
        ca_profiles = data;

        // set the "fetched" property, this can be used by selenium tests to wait until this API has returned
        django.jQuery('meta[name="get-profiles-url"]').attr('fetched', "true");
    });


    // This should be set in the form via intial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery(profile_selector).change(function() {
        if (this.value == '') {
            django.jQuery('.field-profile .profile-desc').hide();
            return;  // do nothing if we don't select a profile
        }

        var profile = ca_profiles[this.value];
        var subject = profile.subject;

        // update subject input field
        django.jQuery.each({
            "C": django.jQuery('.field-subject #country input'),
            "ST": django.jQuery('.field-subject #state input'),
            "L": django.jQuery('.field-subject #location input'),
            "O": django.jQuery('.field-subject #organization input'),
            "OU": django.jQuery('.field-subject #organizational-unit input'),
            "CN": django.jQuery('.field-subject #commonname input'),
            "emailAddress": django.jQuery('.field-subject #e-mail input'),
        }, function(key, input) {
            input.val('' ? typeof subject[key] === 'undefined' : subject[key]);
        });

        // set wether to include the CommonName in the subjectAltName
        cn_in_san = '.field-subject_alternative_name .critical-widget-wrapper input';
        if (typeof profile.cn_in_san === 'undefined' || profile.cn_in_san) {
            django.jQuery(cn_in_san).prop('checked', true);
        } else {
            django.jQuery(cn_in_san).prop('checked', false);
        }

        // update extensions
        extensions = ['key_usage', 'extended_key_usage', 'tls_feature'];
        extensions.map(function(ext) {
            var critical_selector = '.field-' + ext + ' .critical-widget-wrapper input';
            var value_selector = '.field-' + ext + ' select';
            if (profile.extensions[ext] == null) {
                // the extension may be null, meaning the extension should not be added
                django.jQuery(critical_selector).prop('checked', false);
                django.jQuery(value_selector).val([]);
                django.jQuery(value_selector).change();  // so any existing callbacks are called
            } else {
                django.jQuery(critical_selector).prop('checked', profile.extensions[ext].critical);
                django.jQuery(value_selector).val(profile.extensions[ext].value);
                django.jQuery(value_selector).change();  // so any existing callbacks are called
            }
        });

        // update description
        django.jQuery('.field-profile .profile-desc').show();
        django.jQuery('.field-profile .profile-desc').text(profile.description);
    });
});
