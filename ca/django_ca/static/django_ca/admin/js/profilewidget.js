document.addEventListener('DOMContentLoaded', function() {
    var profile_elem = document.querySelector("#profile-data");
    var profile_data = null;

    if (! profile_elem) {
        // poor mans debugging at least telling us what we forgot
        console.log("profile widget: select#profile-data not found, see ProfileWidget class description.");
    } else {
        var profile_data = JSON.parse(profile_elem.textContent);
    }

    document.querySelectorAll(".profile-widget-wrapper").forEach((wrapper) => {
        var select = wrapper.querySelector("select");
        var help = wrapper.querySelector("p.profile-desc");

        // Update description text when selection is updated
        select.addEventListener('change', (event) => {
            var value = select.value;

            // safeguard in case profile data wasn't loaded
            if (! profile_data) {
                return;
            }

            var profile = profile_data[value];

            // Update description
            var description = profile.description;
            if (description) {
                help.textContent = description;
            } else {
                help.textContent = "";  // profiles don't need to have a description
            }
        });
    });
});

django.jQuery(document).ready(function() {
    var ca_profiles;
    var profile_url = django.jQuery('meta[name="get-profiles-url"]').attr('content');

    django.jQuery.get(profile_url).done(function(data) {
        ca_profiles = data;

        // set the "fetched" property, this can be used by selenium tests to wait until this API has returned
        django.jQuery('meta[name="get-profiles-url"]').attr('fetched', "true");
    });


    django.jQuery('.profile-widget-wrapper select').change(function() {
        var profile = ca_profiles[this.value];

        // set whether to include the CommonName in the subjectAltName
        cn_in_san = '.field-subject_alternative_name .labeled-checkbox input';
        if (typeof profile.cn_in_san === 'undefined' || profile.cn_in_san) {
            django.jQuery(cn_in_san).prop('checked', true);
        } else {
            django.jQuery(cn_in_san).prop('checked', false);
        }

        update_extensions(profile.extensions);
    });
});
