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

        // set subject
        var subject = profile.subject;
        if (typeof subject.C !== 'undefined') {
            django.jQuery('.field-subject #country input').val(subject.C);
        }
        if (typeof subject.ST !== 'undefined') {
            django.jQuery('.field-subject #state input').val(subject.ST);
        }
        if (typeof subject.L !== 'undefined') {
            django.jQuery('.field-subject #location input').val(subject.L);
        }
        if (typeof subject.O !== 'undefined') {
            django.jQuery('.field-subject #organization input').val(subject.O);
        }
        if (typeof subject.OU !== 'undefined') {
            django.jQuery('.field-subject #organizational-unit input').val(subject.OU);
        }
        if (typeof subject.CN !== 'undefined') {
            django.jQuery('.field-subject #commonname input').val(subject.CN);
        }

        // set wether to include the CommonName in the subjectAltName
        cn_in_san = '.field-subjectAltName .critical-widget-wrapper input';
        console.log(profile.cn_in_san);
        if (typeof profile.cn_in_san === 'undefined' || profile.cn_in_san) {
            console.log('set to true');
            django.jQuery(cn_in_san).prop('checked', true);
        } else {
            console.log('set to false');
            django.jQuery(cn_in_san).prop('checked', false);
        }

        // update extensions
        extensions = ['keyUsage', 'extendedKeyUsage']
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
