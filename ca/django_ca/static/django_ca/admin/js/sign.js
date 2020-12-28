// see https://docs.djangoproject.com/en/dev/ref/csrf/#ajax
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = django.jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
var csrftoken = getCookie('csrftoken');

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
django.jQuery.ajaxSetup({
    beforeSend: function(xhr, settings) {
        var token = csrftoken ? csrftoken : document.querySelector('[name=csrfmiddlewaretoken]').value;
        if (!csrfSafeMethod(settings.type) && !this.crossDomain && token) {
            xhr.setRequestHeader("X-CSRFToken", token);
        }
    }
});

django.jQuery(document).ready(function() {
    var csr_details_url = django.jQuery('meta[name="csr-details-url"]').attr('value');
    
    django.jQuery('.from-csr-copy').click(function(e) {
        var button = django.jQuery(e.target);
        var wrapper = button.parents('.from-csr');
        var value = wrapper.find('.from-csr-value').text();
        wrapper.parents('.labeled-text-multiwidget').find('input').val(value);
        return false;
    });

    django.jQuery('.field-csr textarea').bind('input', function() {
        var value = django.jQuery(this).val();

        if (! (value.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')
               && value.endsWith('\n-----END CERTIFICATE REQUEST-----'))) {
            django.jQuery('.field-subject #country .from-csr').hide();
            django.jQuery('.field-subject #state .from-csr').hide();
            django.jQuery('.field-subject #location .from-csr').hide();
            django.jQuery('.field-subject #organization .from-csr').hide();
            django.jQuery('.field-subject #organizational-unit .from-csr').hide();
            django.jQuery('.field-subject #commonname .from-csr').hide();
            django.jQuery('.field-subject #e-mail .from-csr').hide();
            return;
        }

        django.jQuery.post(csr_details_url, {
            'csr': value,
        }).done(function(data) {
            django.jQuery.each({
                C: "country",
                ST: "state",
                L: "location",
                O: 'organization',
                OU: 'organizational-unit',
                CN: 'commonname',
                emailAddress: 'e-mail',
            }, function(key, value) {
                var sel = '.field-subject #from-csr-' + value
                if (data.subject[key]) {
                    django.jQuery(sel + ' .from-csr-value').text(data.subject[key]);
                    django.jQuery(sel).show();
                } else {
                    django.jQuery(sel + ' .from-csr-value').text();
                    django.jQuery(sel).hide();
                }
            });
        });
    });
});
