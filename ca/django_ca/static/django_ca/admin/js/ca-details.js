document.addEventListener('DOMContentLoaded', function() {
    var ca_elem = document.querySelector("head script#ca-data");
    var ca_data = JSON.parse(ca_elem.textContent);

    var select = document.querySelector("body select#id_ca");
    select.addEventListener('change', async (event) => {
        var ca = ca_data[select.value];

        // update extensions
        clear_extensions({
            'authority_information_access': null,
            'certificate_policies': null,
            'crl_distribution_points': null,
            'freshest_crl': null,
            'issuer_alternative_name': null,
        })
        await update_extensions(ca.extensions);

        var hash_algorithm_select = document.querySelector('select#id_algorithm');
        if (ca.signature_hash_algorithm === null) {
            hash_algorithm_select.value = "";
        } else {
            hash_algorithm_select.value = ca.signature_hash_algorithm;
        }
    });
});
