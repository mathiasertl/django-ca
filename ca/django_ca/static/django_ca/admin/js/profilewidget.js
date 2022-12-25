django.jQuery(document).ready(function() {
    var ca_profiles;
    var profile_url = django.jQuery('meta[name="get-profiles-url"]').attr('content');
    console.log(profile_url);

    django.jQuery.get(profile_url).done(function(data) {
        ca_profiles = data;

        // set the "fetched" property, this can be used by selenium tests to wait until this API has returned
        django.jQuery('meta[name="get-profiles-url"]').attr('fetched', "true");
    });


    // This should be set in the form via initial
    //var initial_profile = django.jQuery(profile_selector).val();

    django.jQuery('.profile-widget-wrapper select').change(function() {
        if (this.value == '') {
            django.jQuery('.profile-widget-wrapper .profile-desc').hide();
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
            django.jQuery.each(subject, function(index, value) {
                if (value[0] === key) {
                    input.val(value[1]);
                }
            });
        });

        // set wether to include the CommonName in the subjectAltName
        cn_in_san = '.field-subject_alternative_name .labeled-checkbox input';
        if (typeof profile.cn_in_san === 'undefined' || profile.cn_in_san) {
            django.jQuery(cn_in_san).prop('checked', true);
        } else {
            django.jQuery(cn_in_san).prop('checked', false);
        }

        update_extensions(profile.extensions);

        // update description
        console.log('description', profile.description)
        django.jQuery('.profile-widget-wrapper .profile-desc').show();
        django.jQuery('.profile-widget-wrapper .profile-desc').text(profile.description);
    });
});
