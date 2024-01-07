document.addEventListener('DOMContentLoaded', function() {
    var profile_elem = document.querySelector("head script#profile-data");
    var profile_data = null;

    if (! profile_elem) {
        // poor mans debugging at least telling us what we forgot
        console.log("profile widget: select#profile-data not found, see ProfileWidget class description.");
    } else {
        var profile_data = JSON.parse(profile_elem.textContent);
    }

    document.querySelectorAll(".profile-widget-wrapper").forEach((wrapper) => {
        // safeguard in case profile data wasn't loaded
        if (! profile_data) {
            return;
        }

        var select = wrapper.querySelector("select");
        var help = wrapper.querySelector("p.profile-desc");

        // Update description text when selection is updated
        select.addEventListener('change', async (event) => {
            // Get selected profile data
            var profile = profile_data[select.value];

            // Update description
            var description = profile.description;
            if (description) {
                help.textContent = description;
            } else {
                help.textContent = "";  // profiles don't need to have a description
            }

            // Finally, update extensions:
            await update_extensions(profile.extensions);
            clear_extensions(profile.clear_extensions);
        });
    });
});
